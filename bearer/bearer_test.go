package bearer_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/jack-work/jkauthz"
	"github.com/jack-work/jkauthz/bearer"
)

const issuer = "https://auth.kelliher.info"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type issuerFixture struct {
	t     testing.TB
	clock *clock
	mu    sync.Mutex
	keys  map[string]*rsa.PrivateKey
	hits  atomic.Int32
	srv   *httptest.Server
}

func newIssuer(t testing.TB) *issuerFixture {
	f := &issuerFixture{t: t, clock: &clock{t: time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)}, keys: map[string]*rsa.PrivateKey{}}
	f.rotate("k1")
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		var set jose.JSONWebKeySet
		for kid, k := range f.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
		}
		json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *issuerFixture) rotate(kid string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.keys[kid] = k
	f.mu.Unlock()
}

type tok struct {
	kid    string
	key    *rsa.PrivateKey
	typ    string
	claims map[string]any
}

func (f *issuerFixture) access(sub, client string) tok {
	now := f.clock.Now()
	return tok{kid: "k1", typ: "at+jwt", claims: map[string]any{
		"iss":       issuer,
		"sub":       sub,
		"client_id": client,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}}
}

func (f *issuerFixture) sign(t tok) string {
	f.mu.Lock()
	key := t.key
	if key == nil {
		key = f.keys[t.kid]
	}
	f.mu.Unlock()
	opts := (&jose.SignerOptions{}).WithHeader("kid", t.kid)
	if t.typ != "" {
		opts = opts.WithType(jose.ContentType(t.typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, opts)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := josejwt.Signed(signer).Claims(t.claims).Serialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *issuerFixture) verifier(mod func(*bearer.Config)) *bearer.Verifier {
	cfg := bearer.Config{Issuer: issuer, JWKSURL: f.srv.URL, Now: f.clock.Now}
	if mod != nil {
		mod(&cfg)
	}
	v, err := bearer.NewVerifier(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func TestAnAutheliaShapedAccessTokenVerifiesWithoutAudience(t *testing.T) {
	f := newIssuer(t)
	c, err := f.verifier(nil).Verify(context.Background(), f.sign(f.access("u-1", "figaro-cli")))
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientID != "figaro-cli" || c.Subject != "u-1" || c.Issuer != issuer {
		t.Fatalf("%+v", c)
	}
}

func TestVerificationRefuses(t *testing.T) {
	f := newIssuer(t)
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]func(*tok){
		"another issuer":       func(x *tok) { x.claims["iss"] = "https://evil.example" },
		"an expired token":     func(x *tok) { x.claims["exp"] = f.clock.Now().Add(-time.Hour).Unix() },
		"a token with no exp":  func(x *tok) { delete(x.claims, "exp") },
		"a token not yet good": func(x *tok) { x.claims["nbf"] = f.clock.Now().Add(time.Hour).Unix() },
		"a forged signature":   func(x *tok) { x.key = stranger },
		"an unknown kid":       func(x *tok) { x.kid = "k9"; x.key = stranger },
	}
	v := f.verifier(nil)
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			x := f.access("u-1", "figaro-cli")
			mod(&x)
			if _, err := v.Verify(context.Background(), f.sign(x)); !errors.Is(err, bearer.ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestAnUnsignedTokenIsRefused(t *testing.T) {
	f := newIssuer(t)
	none := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2F1dGgua2VsbGloZXIuaW5mbyIsInN1YiI6InUtMSJ9."
	if _, err := f.verifier(nil).Verify(context.Background(), none); err == nil {
		t.Fatal("verified alg none")
	}
}

func TestAConfiguredAudienceIsRequired(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(func(c *bearer.Config) { c.Audience = "figaro://kelliher" })
	x := f.access("u-1", "figaro-cli")
	if _, err := v.Verify(context.Background(), f.sign(x)); !errors.Is(err, bearer.ErrInvalid) {
		t.Fatalf("no aud: %v", err)
	}
	x.claims["aud"] = []string{"figaro://kelliher"}
	if _, err := v.Verify(context.Background(), f.sign(x)); err != nil {
		t.Fatal(err)
	}
}

func TestATypeAllowlistKeepsIDTokensOut(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(func(c *bearer.Config) { c.Types = []string{"at+jwt"} })
	x := f.access("u-1", "figaro-cli")
	if _, err := v.Verify(context.Background(), f.sign(x)); err != nil {
		t.Fatal(err)
	}
	x.typ = "JWT"
	if _, err := v.Verify(context.Background(), f.sign(x)); !errors.Is(err, bearer.ErrInvalid) {
		t.Fatalf("id token passed: %v", err)
	}
}

func TestARotatedKeyIsFetchedOnceItsKidAppears(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(nil)
	if _, err := v.Verify(context.Background(), f.sign(f.access("u", "c"))); err != nil {
		t.Fatal(err)
	}
	f.rotate("k2")
	f.clock.Add(2 * time.Minute)
	x := f.access("u", "c")
	x.kid = "k2"
	if _, err := v.Verify(context.Background(), f.sign(x)); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if n := f.hits.Load(); n != 2 {
		t.Fatalf("jwks fetched %d times, want 2", n)
	}
}

func TestUnknownKidsCannotHammerTheIssuer(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(nil)
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	for range 20 {
		x := f.access("u", "c")
		x.kid, x.key = "nope", stranger
		v.Verify(context.Background(), f.sign(x))
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("jwks fetched %d times inside one refresh window", n)
	}
}

func TestKeysAreRefetchedWhenOld(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(nil)
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	f.clock.Add(2 * time.Hour)
	if _, err := v.Verify(context.Background(), f.sign(f.access("u", "c"))); err != nil {
		t.Fatal(err)
	}
	if n := f.hits.Load(); n != 2 {
		t.Fatalf("jwks fetched %d times, want 2", n)
	}
}

type userinfoFixture struct {
	hits   atomic.Int32
	status atomic.Int32
	mu     sync.Mutex
	body   map[string]any
	ctype  string
	srv    *httptest.Server
}

func newUserinfo(t testing.TB, body map[string]any) *userinfoFixture {
	u := &userinfoFixture{body: body, ctype: "application/json; charset=utf-8"}
	u.status.Store(200)
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		if _, ok := bearer.FromHeader(r.Header.Get("Authorization")); !ok {
			w.WriteHeader(401)
			return
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		w.Header().Set("Content-Type", u.ctype)
		w.WriteHeader(int(u.status.Load()))
		json.NewEncoder(w).Encode(u.body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func TestGroupsComeFromUserinfoNeverFromTheToken(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"figaro-admin"}})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now}}
	x := f.access("u-1", "figaro-cli")
	x.claims["groups"] = []string{"root", "everything"}
	s, err := a.Authenticate(context.Background(), f.sign(x))
	if err != nil {
		t.Fatal(err)
	}
	if s.Principal != (jkauthz.Principal{Kind: jkauthz.KindUser, ID: "gluck"}) {
		t.Fatalf("%+v", s.Principal)
	}
	if !slices.Equal(s.Groups, []string{"figaro-admin"}) {
		t.Fatalf("groups %v", s.Groups)
	}
}

func TestUserinfoIsCachedBrieflyAndAskedAgainAfter(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"a"}})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, TTL: 30 * time.Second, Now: f.clock.Now}}
	raw := f.sign(f.access("u-1", "figaro-cli"))
	for range 5 {
		if _, err := a.Authenticate(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	if n := u.hits.Load(); n != 1 {
		t.Fatalf("userinfo asked %d times inside the ttl", n)
	}
	f.clock.Add(31 * time.Second)
	if _, err := a.Authenticate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if n := u.hits.Load(); n != 2 {
		t.Fatalf("userinfo asked %d times after the ttl", n)
	}
}

func TestAGroupRemovedUpstreamIsGoneOnceTheCacheTurns(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"figaro-admin"}})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now}}
	raw := f.sign(f.access("u-1", "figaro-cli"))
	a.Authenticate(context.Background(), raw)
	u.mu.Lock()
	u.body["groups"] = []string{}
	u.mu.Unlock()
	f.clock.Add(time.Minute)
	s, err := a.Authenticate(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Groups) != 0 {
		t.Fatalf("stale groups %v", s.Groups)
	}
}

func TestUserinfoFailingFailsClosed(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck"})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now}}
	raw := f.sign(f.access("u-1", "figaro-cli"))
	if _, err := a.Authenticate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	u.status.Store(500)
	f.clock.Add(time.Minute)
	if _, err := a.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("served from an expired cache while userinfo was down")
	}
	u.status.Store(401)
	if _, err := a.Authenticate(context.Background(), raw); !errors.Is(err, bearer.ErrInvalid) {
		t.Fatalf("a revoked token: %v", err)
	}
}

func TestTheCacheNeverOutlivesTheToken(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck"})
	r := &bearer.Userinfo{URL: u.srv.URL, TTL: time.Hour, Now: f.clock.Now}
	c := bearer.Claims{Subject: "u-1", Expiry: f.clock.Now().Add(10 * time.Second)}
	if _, err := r.Resolve(context.Background(), "t", c); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(11 * time.Second)
	r.Resolve(context.Background(), "t", c)
	if n := u.hits.Load(); n != 2 {
		t.Fatalf("cached past the token's expiry: %d hits", n)
	}
}

func TestUserinfoForAnotherSubjectIsRefused(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-2", "preferred_username": "mallory"})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now}}
	if _, err := a.Authenticate(context.Background(), f.sign(f.access("u-1", "figaro-cli"))); !errors.Is(err, bearer.ErrInvalid) {
		t.Fatalf("%v", err)
	}
}

func TestASignedUserinfoIsRefusedRatherThanMisread(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck"})
	u.ctype = "application/jwt"
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now}}
	if _, err := a.Authenticate(context.Background(), f.sign(f.access("u-1", "figaro-cli"))); err == nil {
		t.Fatal("read a signed userinfo as json")
	}
}

func TestOnlyAdmittedClientsAuthenticateAndEachResolvesItsOwnWay(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck"})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: bearer.ByClient{
		"figaro-cli":  &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now},
		"sandbox-dev": bearer.Client{Kind: jkauthz.KindSandbox},
	}}

	s, err := a.Authenticate(context.Background(), f.sign(f.access("sandbox-dev", "sandbox-dev")))
	if err != nil {
		t.Fatal(err)
	}
	if s.Principal != (jkauthz.Principal{Kind: jkauthz.KindSandbox, ID: "sandbox-dev"}) || len(s.Groups) != 0 {
		t.Fatalf("%+v", s)
	}
	if u.hits.Load() != 0 {
		t.Fatal("a client token went to userinfo")
	}

	if _, err := a.Authenticate(context.Background(), f.sign(f.access("u-1", "gluck-todo-cli"))); !errors.Is(err, bearer.ErrUnknownClient) {
		t.Fatalf("a token minted for another service was accepted: %v", err)
	}
}

func TestBearerHeaderParsing(t *testing.T) {
	for h, want := range map[string]string{
		"Bearer abc":   "abc",
		"bearer  abc ": "abc",
		"Basic abc":    "",
		"Bearer":       "",
		"Bearer   ":    "",
		"":             "",
	} {
		got, ok := bearer.FromHeader(h)
		if got != want || ok != (want != "") {
			t.Fatalf("%q: got %q %v", h, got, ok)
		}
	}
}

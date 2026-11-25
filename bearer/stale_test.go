package bearer_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jack-work/jkauthz/bearer"
)

func TestKeysKeepVerifyingThroughAnIssuerOutageWithinMaxStale(t *testing.T) {
	f := newIssuer(t)
	var warned int
	v := f.verifier(func(c *bearer.Config) {
		c.MaxStale = 6 * time.Hour
		c.OnStale = func(error) { warned++ }
	})
	if _, err := v.Verify(context.Background(), f.sign(f.access("u", "c"))); err != nil {
		t.Fatal(err)
	}
	f.down.Store(true)
	f.clock.Add(3 * time.Hour)
	for range 3 {
		if _, err := v.Verify(context.Background(), f.sign(f.access("u", "c"))); err != nil {
			t.Fatalf("a token the issuer signed was refused during an outage: %v", err)
		}
	}
	if warned != 1 {
		t.Fatalf("the outage was reported %d times, want once", warned)
	}
}

func TestKeysFailClosedOnceStalenessIsSpent(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(func(c *bearer.Config) { c.MaxStale = time.Hour })
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	f.down.Store(true)
	f.clock.Add(3 * time.Hour)
	_, err := v.Verify(context.Background(), f.sign(f.access("u", "c")))
	if !errors.Is(err, bearer.ErrUnavailable) {
		t.Fatalf("keys older than MaxAge+MaxStale verified, or failed for the wrong reason: %v", err)
	}
}

func TestWithoutMaxStaleAnOutageFailsVerification(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(nil)
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	f.down.Store(true)
	f.clock.Add(2 * time.Hour)
	if _, err := v.Verify(context.Background(), f.sign(f.access("u", "c"))); err == nil {
		t.Fatal("stale keys were used though MaxStale is zero")
	}
}

func TestAnOutageDoesNotSendEveryCallToTheIssuer(t *testing.T) {
	f := newIssuer(t)
	v := f.verifier(func(c *bearer.Config) { c.MaxStale = 6 * time.Hour })
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	f.down.Store(true)
	f.clock.Add(2 * time.Hour)
	before := f.hits.Load()
	for range 20 {
		v.Verify(context.Background(), f.sign(f.access("u", "c")))
	}
	if n := f.hits.Load() - before; n != 1 {
		t.Fatalf("%d fetches inside one retry window, want 1", n)
	}
	f.clock.Add(2 * time.Minute)
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	if n := f.hits.Load() - before; n != 2 {
		t.Fatalf("%d fetches after the retry window, want 2", n)
	}
}

func TestKeysRecoverWhenTheIssuerReturns(t *testing.T) {
	f := newIssuer(t)
	var warned int
	v := f.verifier(func(c *bearer.Config) {
		c.MaxStale = 6 * time.Hour
		c.OnStale = func(error) { warned++ }
	})
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	f.down.Store(true)
	f.clock.Add(2 * time.Hour)
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	f.down.Store(false)
	f.rotate("k2")
	f.clock.Add(2 * time.Minute)
	x := f.access("u", "c")
	x.kid = "k2"
	if _, err := v.Verify(context.Background(), f.sign(x)); err != nil {
		t.Fatalf("a key rotated during the outage is unknown after it: %v", err)
	}
	f.down.Store(true)
	f.clock.Add(2 * time.Hour)
	v.Verify(context.Background(), f.sign(f.access("u", "c")))
	if warned != 2 {
		t.Fatalf("a second outage was reported %d times in total, want 2", warned)
	}
}

type memStore struct {
	mu      sync.Mutex
	raw     []byte
	fetched time.Time
}

func (m *memStore) Load() ([]byte, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.raw, m.fetched, m.raw != nil
}

func (m *memStore) Save(raw []byte, fetched time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.raw, m.fetched = raw, fetched
	return nil
}

func TestAVerifierStartedDuringAnOutageUsesThePersistedKeys(t *testing.T) {
	f := newIssuer(t)
	store := &memStore{}
	first := f.verifier(func(c *bearer.Config) { c.Store = store })
	if _, err := first.Verify(context.Background(), f.sign(f.access("u", "c"))); err != nil {
		t.Fatal(err)
	}
	f.down.Store(true)
	f.clock.Add(30 * time.Minute)
	second := f.verifier(func(c *bearer.Config) { c.Store = store; c.MaxStale = 6 * time.Hour })
	if _, err := second.Verify(context.Background(), f.sign(f.access("u", "c"))); err != nil {
		t.Fatalf("a restart with the issuer down lost the keys: %v", err)
	}
}

func TestUserinfoServesTheLastSubjectThroughAnOutageUntilStaleForOrTokenExpiry(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"a"}})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, StaleFor: 20 * time.Minute, Now: f.clock.Now}}
	raw := f.sign(f.access("u-1", "figaro-cli"))
	if _, err := a.Authenticate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	u.status.Store(503)
	f.clock.Add(time.Minute)
	for range 5 {
		s, err := a.Authenticate(context.Background(), raw)
		if err != nil || s.Principal.ID != "gluck" {
			t.Fatalf("outage refused a subject resolved a minute ago: %v %v", s, err)
		}
	}
	if n := u.hits.Load(); n != 2 {
		t.Fatalf("userinfo asked %d times during one retry window, want 2", n)
	}
	f.clock.Add(30 * time.Minute)
	if _, err := a.Authenticate(context.Background(), raw); !errors.Is(err, bearer.ErrUnavailable) {
		t.Fatalf("a subject served past StaleFor: %v", err)
	}
}

func TestUserinfoRefusalDuringStalenessRevokes(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck"})
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, StaleFor: time.Hour, Now: f.clock.Now}}
	raw := f.sign(f.access("u-1", "figaro-cli"))
	a.Authenticate(context.Background(), raw)
	f.clock.Add(time.Minute)
	u.status.Store(401)
	if _, err := a.Authenticate(context.Background(), raw); !errors.Is(err, bearer.ErrInvalid) {
		t.Fatalf("a revoked token: %v", err)
	}
	u.status.Store(503)
	if _, err := a.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("a revoked token came back from the stale cache")
	}
}

func TestUserinfoOutageWithNothingCachedFailsClosed(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck"})
	u.status.Store(503)
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, StaleFor: time.Hour, Now: f.clock.Now}}
	if _, err := a.Authenticate(context.Background(), f.sign(f.access("u-1", "figaro-cli"))); err == nil {
		t.Fatal("a subject nobody resolved was admitted")
	}
}

type memSubjects struct {
	mu  sync.Mutex
	raw []byte
}

func (m *memSubjects) Load() ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.raw, m.raw != nil
}

func (m *memSubjects) Save(raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.raw = raw
	return nil
}

func TestAUserinfoStartedDuringAnOutageServesTheSubjectsItResolvedBefore(t *testing.T) {
	f := newIssuer(t)
	u := newUserinfo(t, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"a"}})
	store := &memSubjects{}
	raw := f.sign(f.access("u-1", "figaro-cli"))
	first := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, StaleFor: time.Hour, Store: store, Now: f.clock.Now}}
	if _, err := first.Authenticate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	u.status.Store(503)
	f.clock.Add(5 * time.Minute)
	second := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: &bearer.Userinfo{URL: u.srv.URL, StaleFor: time.Hour, Store: store, Now: f.clock.Now}}
	s, err := second.Authenticate(context.Background(), raw)
	if err != nil || s.Principal.ID != "gluck" || len(s.Groups) != 1 {
		t.Fatalf("a restart during an outage lost the resolved subject: %v %v", s, err)
	}
}

func TestAPersistedFetchTimeInTheFutureDoesNotHoldBackTheNextRefresh(t *testing.T) {
	f := newIssuer(t)
	store := &memStore{}
	f.verifier(func(c *bearer.Config) { c.Store = store }).Verify(context.Background(), f.sign(f.access("u", "c")))
	raw, _, _ := store.Load()
	store.Save(raw, f.clock.Now().Add(24*time.Hour))

	v := f.verifier(func(c *bearer.Config) { c.Store = store })
	f.rotate("k2")
	f.clock.Add(2 * time.Minute)
	x := f.access("u", "c")
	x.kid = "k2"
	if _, err := v.Verify(context.Background(), f.sign(x)); err != nil {
		t.Fatalf("a fetch time from the future kept a rotated key unknown: %v", err)
	}
}

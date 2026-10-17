package bearer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jack-work/jkauthz"
)

var ErrUnknownClient = errors.New("bearer: client not admitted")

type Resolver interface {
	Resolve(ctx context.Context, token string, c Claims) (jkauthz.Subject, error)
}

type Client struct {
	Kind jkauthz.Kind
}

func (r Client) Resolve(_ context.Context, _ string, c Claims) (jkauthz.Subject, error) {
	if c.ClientID == "" {
		return jkauthz.Subject{}, fmt.Errorf("%w: no client_id", ErrInvalid)
	}
	return jkauthz.Subject{Principal: jkauthz.Principal{Kind: r.Kind, ID: c.ClientID}}, nil
}

type ByClient map[string]Resolver

func (m ByClient) Resolve(ctx context.Context, token string, c Claims) (jkauthz.Subject, error) {
	r, ok := m[c.ClientID]
	if !ok {
		return jkauthz.Subject{}, fmt.Errorf("%w: %q", ErrUnknownClient, c.ClientID)
	}
	return r.Resolve(ctx, token, c)
}

type Userinfo struct {
	URL     string
	IDClaim string
	TTL     time.Duration
	HTTP    *http.Client
	Now     func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]cached
}

type cached struct {
	subject jkauthz.Subject
	until   time.Time
}

const userinfoCacheCap = 1024

func (u *Userinfo) Resolve(ctx context.Context, token string, c Claims) (jkauthz.Subject, error) {
	now := u.now()
	key := sha256.Sum256([]byte(token))
	u.mu.Lock()
	if e, ok := u.cache[key]; ok && now.Before(e.until) {
		u.mu.Unlock()
		return e.subject, nil
	}
	u.mu.Unlock()

	s, err := u.fetch(ctx, token, c)
	if err != nil {
		return jkauthz.Subject{}, err
	}
	until := now.Add(u.ttl())
	if c.Expiry.Before(until) {
		until = c.Expiry
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cache == nil {
		u.cache = map[[32]byte]cached{}
	}
	if len(u.cache) >= userinfoCacheCap {
		for k, e := range u.cache {
			if !now.Before(e.until) {
				delete(u.cache, k)
			}
		}
		if len(u.cache) >= userinfoCacheCap {
			clear(u.cache)
		}
	}
	u.cache[key] = cached{subject: s, until: until}
	return s, nil
}

func (u *Userinfo) fetch(ctx context.Context, token string, c Claims) (jkauthz.Subject, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return jkauthz.Subject{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	client := u.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return jkauthz.Subject{}, fmt.Errorf("bearer: userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return jkauthz.Subject{}, fmt.Errorf("%w: userinfo %s", ErrInvalid, resp.Status)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return jkauthz.Subject{}, fmt.Errorf("bearer: userinfo content type %q, want application/json", mt)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return jkauthz.Subject{}, fmt.Errorf("bearer: userinfo: %w", err)
	}
	if sub, _ := body["sub"].(string); c.Subject != "" && sub != c.Subject {
		return jkauthz.Subject{}, fmt.Errorf("%w: userinfo sub %q does not match token sub %q", ErrInvalid, sub, c.Subject)
	}
	claim := u.IDClaim
	if claim == "" {
		claim = "preferred_username"
	}
	id, _ := body[claim].(string)
	if strings.TrimSpace(id) == "" {
		return jkauthz.Subject{}, fmt.Errorf("%w: userinfo has no %s", ErrInvalid, claim)
	}
	var groups []string
	if raw, ok := body["groups"].([]any); ok {
		for _, g := range raw {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
	}
	return jkauthz.Subject{
		Principal: jkauthz.Principal{Kind: jkauthz.KindUser, ID: id},
		Groups:    groups,
	}, nil
}

func (u *Userinfo) ttl() time.Duration {
	if u.TTL > 0 {
		return u.TTL
	}
	return 30 * time.Second
}

func (u *Userinfo) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

type Authenticator struct {
	Verifier *Verifier
	Resolver Resolver
}

func (a Authenticator) Authenticate(ctx context.Context, token string) (jkauthz.Subject, error) {
	c, err := a.Verifier.Verify(ctx, token)
	if err != nil {
		return jkauthz.Subject{}, err
	}
	return a.Resolver.Resolve(ctx, token, c)
}

func FromHeader(h string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

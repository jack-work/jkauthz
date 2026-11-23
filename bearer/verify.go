package bearer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

var ErrInvalid = errors.New("bearer: invalid token")

// ErrUnavailable marks a failure to reach the issuer (network, 5xx, 429), as
// opposed to the issuer refusing the token, which is ErrInvalid.
var ErrUnavailable = errors.New("bearer: issuer unavailable")

// KeyStore persists the issuer's JWKS body so a restart while the issuer is
// unreachable still verifies tokens it could verify before.
type KeyStore interface {
	Load() (jwks []byte, fetched time.Time, ok bool)
	Save(jwks []byte, fetched time.Time) error
}

type Claims struct {
	Issuer   string
	Subject  string
	ClientID string
	Expiry   time.Time
	Extra    map[string]any
}

type Config struct {
	Issuer     string
	JWKSURL    string
	Audience   string
	Types      []string
	Algorithms []jose.SignatureAlgorithm
	Leeway     time.Duration
	MinRefresh time.Duration
	MaxAge     time.Duration
	// MaxStale lets a verifier keep using the last good key set for this long
	// past MaxAge when a refresh fails. Zero keeps the strict behaviour: a
	// failed refresh fails verification.
	MaxStale time.Duration
	// OnStale is called once per outage, the first time a key set is used
	// after a failed refresh.
	OnStale func(err error)
	// Store, when set, is loaded at construction and saved after each
	// successful fetch.
	Store KeyStore
	HTTP  *http.Client
	Now   func() time.Time
}

type Verifier struct {
	cfg  Config
	keys *keySet
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.JWKSURL == "" {
		return nil, fmt.Errorf("bearer: issuer and jwks url are required")
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.MinRefresh == 0 {
		cfg.MinRefresh = time.Minute
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = time.Hour
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ks := &keySet{cfg: &cfg}
	ks.restore()
	return &Verifier{cfg: cfg, keys: ks}, nil
}

func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	tok, err := josejwt.ParseSigned(raw, v.cfg.Algorithms)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(tok.Headers) != 1 {
		return Claims{}, fmt.Errorf("%w: %d signatures", ErrInvalid, len(tok.Headers))
	}
	h := tok.Headers[0]
	if len(v.cfg.Types) > 0 {
		typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
		if !slices.Contains(v.cfg.Types, typ) {
			return Claims{}, fmt.Errorf("%w: typ %q", ErrInvalid, typ)
		}
	}
	key, err := v.keys.lookup(ctx, h.KeyID)
	if err != nil {
		return Claims{}, err
	}
	var std josejwt.Claims
	extra := map[string]any{}
	if err := tok.Claims(key, &std, &extra); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if std.Expiry == nil {
		return Claims{}, fmt.Errorf("%w: no exp", ErrInvalid)
	}
	now := v.cfg.Now()
	if err := std.ValidateWithLeeway(josejwt.Expected{Issuer: v.cfg.Issuer, Time: now}, v.cfg.Leeway); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if v.cfg.Audience != "" && !std.Audience.Contains(v.cfg.Audience) {
		return Claims{}, fmt.Errorf("%w: audience %v", ErrInvalid, []string(std.Audience))
	}
	clientID, _ := extra["client_id"].(string)
	return Claims{
		Issuer:   std.Issuer,
		Subject:  std.Subject,
		ClientID: clientID,
		Expiry:   std.Expiry.Time(),
		Extra:    extra,
	}, nil
}

type keySet struct {
	cfg      *Config
	mu       sync.Mutex
	set      jose.JSONWebKeySet
	fetched  time.Time
	failedAt time.Time
	failure  error
	warned   bool
}

func (k *keySet) restore() {
	if k.cfg.Store == nil {
		return
	}
	raw, fetched, ok := k.cfg.Store.Load()
	if !ok {
		return
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal(raw, &set) != nil || len(set.Keys) == 0 {
		return
	}
	k.set, k.fetched = set, fetched
}

func (k *keySet) usableStale(now time.Time) bool {
	return k.cfg.MaxStale > 0 && !k.fetched.IsZero() && now.Sub(k.fetched) < k.cfg.MaxAge+k.cfg.MaxStale
}

func (k *keySet) lookup(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.cfg.Now()
	if k.fetched.IsZero() || now.Sub(k.fetched) >= k.cfg.MaxAge {
		if err := k.refresh(ctx, now); err != nil && !k.usableStale(now) {
			return jose.JSONWebKey{}, err
		}
	}
	if key, ok := k.find(kid); ok {
		return key, nil
	}
	if now.Sub(k.fetched) < k.cfg.MinRefresh {
		return jose.JSONWebKey{}, fmt.Errorf("%w: unknown kid %q", ErrInvalid, kid)
	}
	if err := k.refresh(ctx, now); err != nil {
		return jose.JSONWebKey{}, err
	}
	if key, ok := k.find(kid); ok {
		return key, nil
	}
	return jose.JSONWebKey{}, fmt.Errorf("%w: unknown kid %q", ErrInvalid, kid)
}

func (k *keySet) refresh(ctx context.Context, now time.Time) error {
	if k.usableStale(now) && !k.failedAt.IsZero() && now.Sub(k.failedAt) < k.cfg.MinRefresh {
		return k.failure
	}
	err := k.fetch(ctx)
	if err == nil {
		k.failedAt, k.failure, k.warned = time.Time{}, nil, false
		return nil
	}
	k.failedAt, k.failure = now, err
	if k.usableStale(now) && !k.warned {
		k.warned = true
		if k.cfg.OnStale != nil {
			k.cfg.OnStale(err)
		}
	}
	return err
}

func (k *keySet) find(kid string) (jose.JSONWebKey, bool) {
	var found []jose.JSONWebKey
	for _, key := range k.set.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if kid == "" || key.KeyID == kid {
			found = append(found, key)
		}
	}
	if len(found) != 1 {
		return jose.JSONWebKey{}, false
	}
	return found[0], true
}

func (k *keySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := k.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: jwks: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: jwks: %s", ErrUnavailable, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return fmt.Errorf("%w: jwks: %v", ErrUnavailable, err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("bearer: jwks: %w", err)
	}
	k.set = set
	k.fetched = k.cfg.Now()
	if k.cfg.Store != nil {
		_ = k.cfg.Store.Save(raw, k.fetched)
	}
	return nil
}

const maxJWKSBytes = 1 << 20

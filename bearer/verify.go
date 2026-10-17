package bearer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

var ErrInvalid = errors.New("bearer: invalid token")

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
	HTTP       *http.Client
	Now        func() time.Time
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
	return &Verifier{cfg: cfg, keys: &keySet{cfg: &cfg}}, nil
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
	cfg     *Config
	mu      sync.Mutex
	set     jose.JSONWebKeySet
	fetched time.Time
}

func (k *keySet) lookup(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.cfg.Now()
	if k.fetched.IsZero() || now.Sub(k.fetched) >= k.cfg.MaxAge {
		if err := k.fetch(ctx); err != nil {
			return jose.JSONWebKey{}, err
		}
	}
	if key, ok := k.find(kid); ok {
		return key, nil
	}
	if now.Sub(k.fetched) < k.cfg.MinRefresh {
		return jose.JSONWebKey{}, fmt.Errorf("%w: unknown kid %q", ErrInvalid, kid)
	}
	if err := k.fetch(ctx); err != nil {
		return jose.JSONWebKey{}, err
	}
	if key, ok := k.find(kid); ok {
		return key, nil
	}
	return jose.JSONWebKey{}, fmt.Errorf("%w: unknown kid %q", ErrInvalid, kid)
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
		return fmt.Errorf("bearer: jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bearer: jwks: %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("bearer: jwks: %w", err)
	}
	k.set = set
	k.fetched = k.cfg.Now()
	return nil
}

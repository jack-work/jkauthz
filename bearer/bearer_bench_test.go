package bearer_test

import (
	"context"
	"testing"

	"github.com/jack-work/jkauthz"
	"github.com/jack-work/jkauthz/bearer"
)

func BenchmarkVerify(b *testing.B) {
	f := newIssuer(b)
	v := f.verifier(nil)
	raw := f.sign(f.access("u-1", "figaro-cli"))
	ctx := context.Background()
	if _, err := v.Verify(ctx, raw); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Verify(ctx, raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthenticate(b *testing.B) {
	f := newIssuer(b)
	u := newUserinfo(b, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"figaro-admin"}})
	ctx := context.Background()
	user := f.sign(f.access("u-1", "figaro-cli"))
	box := f.sign(f.access("sandbox-dev", "sandbox-dev"))
	a := bearer.Authenticator{Verifier: f.verifier(nil), Resolver: bearer.ByClient{
		"figaro-cli":  &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now},
		"sandbox-dev": bearer.Client{Kind: jkauthz.KindSandbox},
	}}
	for name, raw := range map[string]string{"user-userinfo-cached": user, "sandbox-client": box} {
		if _, err := a.Authenticate(ctx, raw); err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.Authenticate(ctx, raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUserinfo(b *testing.B) {
	f := newIssuer(b)
	u := newUserinfo(b, map[string]any{"sub": "u-1", "preferred_username": "gluck", "groups": []string{"figaro-admin"}})
	c := bearer.Claims{Subject: "u-1", Expiry: f.clock.Now().Add(1 << 40)}
	ctx := context.Background()
	b.Run("hit", func(b *testing.B) {
		r := &bearer.Userinfo{URL: u.srv.URL, Now: f.clock.Now}
		if _, err := r.Resolve(ctx, "tok", c); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := r.Resolve(ctx, "tok", c); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("miss-loopback", func(b *testing.B) {
		r := &bearer.Userinfo{URL: u.srv.URL, TTL: 1, Now: f.clock.Now}
		b.ReportAllocs()
		for b.Loop() {
			f.clock.Add(2)
			if _, err := r.Resolve(ctx, "tok", c); err != nil {
				b.Fatal(err)
			}
		}
	})
}

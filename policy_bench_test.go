package jkauthz_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jack-work/jkauthz"
)

func largePolicy(bindings int) string {
	var b strings.Builder
	b.WriteString(estate)
	for i := range bindings {
		fmt.Fprintf(&b, "\n[[bind]]\nrole = \"sender\"\nprincipals = [\"sandbox:filler-%d\"]\n", i)
	}
	return b.String()
}

func BenchmarkAllow(b *testing.B) {
	for _, n := range []int{2, 100} {
		p, err := jkauthz.Compile([]byte(largePolicy(n)), figaroSchema)
		if err != nil {
			b.Fatal(err)
		}
		owner := jkauthz.Subject{Principal: jkauthz.Principal{Kind: jkauthz.KindUser, ID: "1000"}}
		box := jkauthz.Subject{Principal: jkauthz.Principal{Kind: jkauthz.KindSandbox, ID: "dev-3"}}
		stranger := jkauthz.Subject{Principal: jkauthz.Principal{Kind: jkauthz.KindUser, ID: "1001"}}
		res := aria{ID: "a1", Owner: box.Principal}
		for name, c := range map[string]struct {
			s    jkauthz.Subject
			verb string
		}{
			"owner-first-binding":  {owner, "send"},
			"sandbox-owner-self":   {box, "send"},
			"sandbox-denied":       {box, "kill"},
			"stranger-denied-scan": {stranger, "read"},
		} {
			b.Run(fmt.Sprintf("bindings=%d/%s", n, name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p.Allow(c.s, c.verb, res)
				}
			})
		}
	}
}

func BenchmarkStoreAllow(b *testing.B) {
	s := jkauthz.NewStore(figaroSchema)
	if err := s.LoadBytes([]byte(estate)); err != nil {
		b.Fatal(err)
	}
	owner := jkauthz.Subject{Principal: jkauthz.Principal{Kind: jkauthz.KindUser, ID: "1000"}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Allow(owner, "read", aria{})
		}
	})
}

func BenchmarkCompile(b *testing.B) {
	src := []byte(largePolicy(100))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := jkauthz.Compile(src, figaroSchema); err != nil {
			b.Fatal(err)
		}
	}
}

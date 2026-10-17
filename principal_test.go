package jkauthz_test

import (
	"testing"

	"github.com/jack-work/jkauthz"
)

func TestPrincipalTextRoundTrips(t *testing.T) {
	for _, s := range []string{
		"user:1000",
		"user:gluck",
		"sandbox:spiffe://kelliher.info/sandbox/dev/3",
		"node:spain2",
		"spain2/user:1000",
	} {
		p, err := jkauthz.ParsePrincipal(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if p.String() != s {
			t.Fatalf("%s rendered as %s", s, p)
		}
	}
}

func TestTheIDKeepsEverythingAfterTheFirstColon(t *testing.T) {
	p, err := jkauthz.ParsePrincipal("sandbox:spiffe://kelliher.info/sandbox/dev/3")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != jkauthz.KindSandbox || p.ID != "spiffe://kelliher.info/sandbox/dev/3" || p.Node != "" {
		t.Fatalf("%+v", p)
	}
}

func TestMalformedPrincipalsAreRefused(t *testing.T) {
	for _, s := range []string{"", "user", "user:", ":1000", "/user:1", "a/b/user:1", "us er:1", "*:1"} {
		if p, err := jkauthz.ParsePrincipal(s); err == nil {
			t.Fatalf("%q parsed as %+v", s, p)
		}
	}
}

package jkauthz_test

import (
	"slices"
	"testing"

	"github.com/jack-work/jkauthz"
)

func TestTheVerbEndsAtTheFirstColonSoObjectsKeepTheirs(t *testing.T) {
	g, err := jkauthz.ParseGrant("send:role:@herald")
	if err != nil || g.Verb != "send" || g.Object != "role:@herald" {
		t.Fatalf("%+v %v", g, err)
	}
	if g.String() != "send:role:@herald" {
		t.Fatal(g.String())
	}
}

func TestParseGrantRefusesWhatIsNotVerbColonObject(t *testing.T) {
	for _, s := range []string{"", "read", "read:", ":aria:x", "re*d:x", "read:aria: x", "a/b:x"} {
		if _, err := jkauthz.ParseGrant(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestCanonicalDropsDuplicatesAndCoveredGrantsAndSortsBySchema(t *testing.T) {
	gs, err := figaroSchema.ParseGrants([]string{
		"send:role:@herald", "read:aria:b", "read:*", "send:aria:a", "kill:owner:self",
		"*:owner:self", "send:aria:a", "listen:aria:a",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*:owner:self", "read:*", "listen:aria:a", "send:aria:a", "send:role:@herald"}
	if !slices.Equal(gs.Strings(), want) {
		t.Fatalf("got %v want %v", gs.Strings(), want)
	}
}

func TestCanonicalFormReadsBackToItself(t *testing.T) {
	gs, err := figaroSchema.ParseGrants([]string{"create:*", "send:role:@herald", "read:owner:self", "read:role:@herald"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := figaroSchema.ParseGrants(gs.Strings())
	if err != nil || !slices.Equal(gs, again) {
		t.Fatalf("%v != %v (%v)", gs, again, err)
	}
	if gs.String() != "read:owner:self, read:role:@herald, send:role:@herald, create:*" {
		t.Fatal(gs.String())
	}
}

func TestAnythingCoversEverythingAndNothingElseDoes(t *testing.T) {
	all, _ := figaroSchema.ParseGrants([]string{"*:*", "read:aria:x"})
	if len(all) != 1 || !all.Covers(jkauthz.Grant{Verb: "admin", Object: "aria:y"}) {
		t.Fatalf("%v", all)
	}
	some, _ := figaroSchema.ParseGrants([]string{"read:*", "*:aria:x"})
	for g, want := range map[jkauthz.Grant]bool{
		{Verb: "read", Object: "owner:self"}: true,
		{Verb: "kill", Object: "aria:x"}:     true,
		{Verb: "kill", Object: "aria:y"}:     false,
		{Verb: "*", Object: "aria:x"}:        true,
		{Verb: "*", Object: "*"}:             false,
	} {
		if some.Covers(g) != want {
			t.Errorf("%v covers %v: want %v", some, g, want)
		}
	}
}

func TestParseGrantsValidatesAgainstTheSchema(t *testing.T) {
	for _, s := range []string{"sned:*", "read:owner:me"} {
		if _, err := figaroSchema.ParseGrants([]string{s}); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestBindsAnswersWhetherAnyRoleIsBound(t *testing.T) {
	p := compile(t, estate)
	for s, want := range map[string]bool{"user:1000": true, "sandbox:dev-3": true, "user:1001": false} {
		if got := p.Binds(jkauthz.Subject{Principal: principal(t, s)}); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
	if !p.Binds(jkauthz.Subject{Principal: principal(t, "user:x"), Groups: []string{"figaro-admin"}}) {
		t.Error("group binding")
	}
	if p.Binds(jkauthz.Subject{}) {
		t.Error("zero subject")
	}
}

func TestRolesShowsEachRoleInCanonicalForm(t *testing.T) {
	roles := compile(t, estate).Roles()
	if got := roles["owner"].String(); got != "*:*" {
		t.Fatal(got)
	}
	if got := roles["sender"].String(); got != "read:owner:self, read:role:@herald, listen:owner:self, listen:role:@herald, send:owner:self, send:role:@herald, create:*" {
		t.Fatal(got)
	}
}

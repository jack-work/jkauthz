package jkauthz_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jack-work/jkauthz"
)

type aria struct {
	ID    string
	Owner jkauthz.Principal
	Roles []string
}

type ariaSelectors struct{}

func (ariaSelectors) Validate(sel string) error {
	switch {
	case sel == "owner:self":
		return nil
	case strings.HasPrefix(sel, "aria:") && len(sel) > len("aria:"):
		return nil
	case strings.HasPrefix(sel, "role:@") && len(sel) > len("role:@"):
		return nil
	}
	return fmt.Errorf("unknown selector")
}

func (ariaSelectors) Match(sel string, s jkauthz.Subject, a aria) bool {
	switch {
	case sel == "owner:self":
		return a.Owner == s.Principal
	case strings.HasPrefix(sel, "aria:"):
		return a.ID == strings.TrimPrefix(sel, "aria:")
	case strings.HasPrefix(sel, "role:"):
		for _, r := range a.Roles {
			if r == strings.TrimPrefix(sel, "role:") {
				return true
			}
		}
	}
	return false
}

var figaroSchema = jkauthz.Schema[aria]{
	Verbs:     []string{"read", "listen", "send", "fork", "set", "create", "kill", "admin"},
	Selectors: ariaSelectors{},
}

const estate = `
[roles.owner]
grants = [{ verbs = ["*"], on = ["*"] }]

[roles.sender]
grants = [
  { verbs = ["read", "listen", "send"], on = ["owner:self", "role:@herald"] },
  { verbs = ["create"], on = ["*"] },
]

[[bind]]
role = "owner"
principals = ["user:1000"]
groups = ["figaro-admin"]

[[bind]]
role = "sender"
principals = ["sandbox:dev-3"]
`

func compile(t *testing.T, src string) *jkauthz.Policy[aria] {
	t.Helper()
	p, err := jkauthz.Compile([]byte(src), figaroSchema)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func principal(t *testing.T, s string) jkauthz.Principal {
	t.Helper()
	p, err := jkauthz.ParsePrincipal(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestABoundPrincipalHoldsItsRoleEverywhereTheRoleReaches(t *testing.T) {
	p := compile(t, estate)
	me := jkauthz.Subject{Principal: principal(t, "user:1000")}
	d := p.Allow(me, "kill", aria{ID: "abcd1234"})
	if !d.Allowed || d.Role != "owner" {
		t.Fatalf("owner may kill anything: %+v", d)
	}
}

func TestAGroupBindingAdmitsAnyMemberWhateverTheirPrincipal(t *testing.T) {
	p := compile(t, estate)
	s := jkauthz.Subject{Principal: principal(t, "user:gluck"), Groups: []string{"figaro-admin"}}
	d := p.Allow(s, "admin", aria{})
	if !d.Allowed || !strings.Contains(d.Reason(), "group figaro-admin") {
		t.Fatalf("group member is owner: %+v", d)
	}
}

func TestSelectorsAreMatchedByTheHostAgainstTheResource(t *testing.T) {
	p := compile(t, estate)
	box := principal(t, "sandbox:dev-3")
	s := jkauthz.Subject{Principal: box}

	if d := p.Allow(s, "send", aria{ID: "a1", Owner: box}); !d.Allowed || d.Selector != "owner:self" {
		t.Fatalf("a sandbox may send to an aria it minted: %+v", d)
	}
	if d := p.Allow(s, "send", aria{ID: "a2", Roles: []string{"@herald"}}); !d.Allowed || d.Selector != "role:@herald" {
		t.Fatalf("a sandbox may send to the herald role: %+v", d)
	}
	if d := p.Allow(s, "send", aria{ID: "a3", Owner: principal(t, "user:1000")}); d.Allowed {
		t.Fatalf("a sandbox may not send to someone else's aria: %+v", d)
	}
}

func TestAVerbOutsideEveryHeldRoleIsDeniedWithTheRolesNamed(t *testing.T) {
	p := compile(t, estate)
	box := principal(t, "sandbox:dev-3")
	d := p.Allow(jkauthz.Subject{Principal: box}, "kill", aria{Owner: box})
	if d.Allowed {
		t.Fatal("sender cannot kill")
	}
	if !strings.Contains(d.Reason(), "sender") || !strings.Contains(d.Reason(), "kill") {
		t.Fatalf("reason names the held roles and the verb: %q", d.Reason())
	}
}

func TestAnUnboundPrincipalIsDenied(t *testing.T) {
	p := compile(t, estate)
	d := p.Allow(jkauthz.Subject{Principal: principal(t, "user:1001")}, "read", aria{})
	if d.Allowed || !strings.Contains(d.Reason(), "holds no role") {
		t.Fatalf("%+v", d)
	}
}

func TestTheZeroSubjectIsDeniedEvenWhereAGrantSaysAnything(t *testing.T) {
	p := compile(t, estate)
	if d := p.Allow(jkauthz.Subject{}, "read", aria{}); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestAVerbTheSchemaDoesNotKnowIsDeniedNotPanicked(t *testing.T) {
	p := compile(t, estate)
	d := p.Allow(jkauthz.Subject{Principal: principal(t, "user:1000")}, "teleport", aria{})
	if d.Allowed || !strings.Contains(d.Reason(), "unknown verb") {
		t.Fatalf("%+v", d)
	}
}

func TestAPrincipalOnAnotherNodeIsNotTheLocalPrincipalOfTheSameName(t *testing.T) {
	p := compile(t, estate)
	remote := jkauthz.Subject{Principal: principal(t, "spain2/user:1000")}
	if d := p.Allow(remote, "read", aria{}); d.Allowed {
		t.Fatalf("uid 1000 on spain2 is not uid 1000 here: %+v", d)
	}
	q := compile(t, `
[roles.peer]
grants = [{ verbs = ["read"], on = ["*"] }]
[[bind]]
role = "peer"
principals = ["spain2/user:1000"]
`)
	if d := q.Allow(remote, "read", aria{}); !d.Allowed {
		t.Fatalf("a node-qualified binding admits it: %+v", d)
	}
}

func TestAKindWildcardAdmitsEveryIDOfThatKindAndNothingElse(t *testing.T) {
	p := compile(t, `
[roles.reader]
grants = [{ verbs = ["read"], on = ["*"] }]
[[bind]]
role = "reader"
principals = ["sandbox:*"]
`)
	if d := p.Allow(jkauthz.Subject{Principal: principal(t, "sandbox:anything")}, "read", aria{}); !d.Allowed {
		t.Fatalf("%+v", d)
	}
	if d := p.Allow(jkauthz.Subject{Principal: principal(t, "user:anything")}, "read", aria{}); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	p := compile(t, "")
	if d := p.Allow(jkauthz.Subject{Principal: principal(t, "user:1000")}, "read", aria{}); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestCompileRefusesWhatWouldOtherwiseFailSilently(t *testing.T) {
	cases := map[string]string{
		"unknown verb": `
[roles.r]
grants = [{ verbs = ["sned"], on = ["*"] }]`,
		"unknown selector": `
[roles.r]
grants = [{ verbs = ["read"], on = ["owner:me"] }]`,
		"unknown role in binding": `
[roles.r]
grants = [{ verbs = ["read"], on = ["*"] }]
[[bind]]
role = "rr"
principals = ["user:1"]`,
		"binding to nobody": `
[roles.r]
grants = [{ verbs = ["read"], on = ["*"] }]
[[bind]]
role = "r"`,
		"role that grants nothing": `
[roles.r]
grants = []`,
		"grant without selectors": `
[roles.r]
grants = [{ verbs = ["read"] }]`,
		"misspelled key": `
[roles.r]
grant = [{ verbs = ["read"], on = ["*"] }]`,
		"malformed principal": `
[roles.r]
grants = [{ verbs = ["read"], on = ["*"] }]
[[bind]]
role = "r"
principals = ["1000"]`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := jkauthz.Compile([]byte(src), figaroSchema); err == nil {
				t.Fatal("compiled")
			}
		})
	}
}

func TestASchemaWithoutSelectorsAcceptsOnlyTheWildcard(t *testing.T) {
	schema := jkauthz.Schema[struct{}]{Verbs: []string{"use"}}
	if _, err := jkauthz.Compile([]byte(`
[roles.r]
grants = [{ verbs = ["use"], on = ["*"] }]`), schema); err != nil {
		t.Fatal(err)
	}
	if _, err := jkauthz.Compile([]byte(`
[roles.r]
grants = [{ verbs = ["use"], on = ["thing:1"] }]`), schema); err == nil {
		t.Fatal("compiled a selector nothing can match")
	}
}

func TestAStoreWithNothingLoadedDenies(t *testing.T) {
	s := jkauthz.NewStore(figaroSchema)
	d := s.Allow(jkauthz.Subject{Principal: principal(t, "user:1000")}, "read", aria{})
	if d.Allowed || d.Reason() != "no policy loaded" {
		t.Fatalf("%+v", d)
	}
}

func TestAMissingFileLeavesTheStoreDenying(t *testing.T) {
	s := jkauthz.NewStore(figaroSchema)
	if err := s.Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("loaded a missing file")
	}
	if d := s.Allow(jkauthz.Subject{Principal: principal(t, "user:1000")}, "read", aria{}); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestAReloadChangesTheAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	write := func(src string) {
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := jkauthz.NewStore(figaroSchema)
	box := jkauthz.Subject{Principal: principal(t, "sandbox:dev-3")}

	write(estate)
	if err := s.Load(path); err != nil {
		t.Fatal(err)
	}
	if d := s.Allow(box, "kill", aria{Owner: box.Principal}); d.Allowed {
		t.Fatalf("before: %+v", d)
	}

	write(estate + `
[[bind]]
role = "owner"
principals = ["sandbox:dev-3"]
`)
	if err := s.Load(path); err != nil {
		t.Fatal(err)
	}
	if d := s.Allow(box, "kill", aria{Owner: box.Principal}); !d.Allowed {
		t.Fatalf("after: %+v", d)
	}
}

func TestAFailedReloadKeepsThePolicyThatWasServing(t *testing.T) {
	s := jkauthz.NewStore(figaroSchema)
	if err := s.LoadBytes([]byte(estate)); err != nil {
		t.Fatal(err)
	}
	before := s.Policy()
	if err := s.LoadBytes([]byte(`[roles.broken`)); err == nil {
		t.Fatal("loaded garbage")
	}
	if s.Policy() != before {
		t.Fatal("a failed load replaced the policy")
	}
	if d := s.Allow(jkauthz.Subject{Principal: principal(t, "user:1000")}, "read", aria{}); !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestReadersNeverSeeAHalfLoadedPolicy(t *testing.T) {
	s := jkauthz.NewStore(figaroSchema)
	if err := s.LoadBytes([]byte(estate)); err != nil {
		t.Fatal(err)
	}
	me := jkauthz.Subject{Principal: principal(t, "user:1000")}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 500 {
				if d := s.Allow(me, "read", aria{}); !d.Allowed {
					t.Errorf("%+v", d)
					return
				}
			}
		})
	}
	for range 200 {
		if err := s.LoadBytes([]byte(estate)); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

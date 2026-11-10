package jkauthz

import (
	"fmt"
	"slices"
	"strings"
)

type Grant struct {
	Verb   string
	Object string
}

func ParseGrant(s string) (Grant, error) {
	verb, object, ok := strings.Cut(s, ":")
	if !ok || verb == "" || object == "" {
		return Grant{}, fmt.Errorf("grant %q: want verb:object", s)
	}
	if verb != Any && strings.ContainsAny(verb, "/ \t*") {
		return Grant{}, fmt.Errorf("grant %q: verb %q contains a reserved character", s, verb)
	}
	if strings.ContainsAny(object, " \t") {
		return Grant{}, fmt.Errorf("grant %q: object contains whitespace", s)
	}
	return Grant{Verb: verb, Object: object}, nil
}

func (g Grant) String() string { return g.Verb + ":" + g.Object }

func (g Grant) Covers(h Grant) bool {
	return (g.Verb == Any || g.Verb == h.Verb) && (g.Object == Any || g.Object == h.Object)
}

type Grants []Grant

func (gs Grants) Covers(h Grant) bool {
	return slices.ContainsFunc(gs, func(g Grant) bool { return g.Covers(h) })
}

func (gs Grants) Strings() []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.String()
	}
	return out
}

func (gs Grants) String() string { return strings.Join(gs.Strings(), ", ") }

func (s Schema[R]) ParseGrants(texts []string) (Grants, error) {
	gs := make(Grants, 0, len(texts))
	for _, t := range texts {
		g, err := ParseGrant(t)
		if err != nil {
			return nil, err
		}
		if err := s.validate(g); err != nil {
			return nil, fmt.Errorf("grant %q: %w", t, err)
		}
		gs = append(gs, g)
	}
	return s.Canonical(gs), nil
}

func (s Schema[R]) validate(g Grant) error {
	if g.Verb != Any && !slices.Contains(s.Verbs, g.Verb) {
		return fmt.Errorf("unknown verb %q", g.Verb)
	}
	if g.Object == Any {
		return nil
	}
	if s.Selectors == nil {
		return fmt.Errorf("selector %q but the schema matches only %q", g.Object, Any)
	}
	if err := s.Selectors.Validate(g.Object); err != nil {
		return fmt.Errorf("selector %q: %w", g.Object, err)
	}
	return nil
}

func (s Schema[R]) Canonical(gs Grants) Grants {
	out := make(Grants, 0, len(gs))
	for i, g := range gs {
		covered := false
		for j, h := range gs {
			if i != j && h.Covers(g) && (h != g || j < i) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b Grant) int {
		if c := s.verbRank(a.Verb) - s.verbRank(b.Verb); c != 0 {
			return c
		}
		if a.Verb != b.Verb {
			return strings.Compare(a.Verb, b.Verb)
		}
		if (a.Object == Any) != (b.Object == Any) {
			if a.Object == Any {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Object, b.Object)
	})
	return out
}

func (s Schema[R]) verbRank(v string) int {
	if v == Any {
		return -1
	}
	if i := slices.Index(s.Verbs, v); i >= 0 {
		return i
	}
	return len(s.Verbs)
}

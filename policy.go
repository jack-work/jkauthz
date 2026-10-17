package jkauthz

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/BurntSushi/toml"
)

const Any = "*"

type Selectors[R any] interface {
	Validate(selector string) error
	Match(selector string, s Subject, r R) bool
}

type Schema[R any] struct {
	Verbs     []string
	Selectors Selectors[R]
}

type Decision struct {
	Allowed  bool
	Role     string
	Selector string

	cause   cause
	subject Principal
	verb    string
	group   string
	held    []string
}

type cause uint8

const (
	causeAllowed cause = iota
	causeNoPolicy
	causeUnknownVerb
	causeNoPrincipal
	causeNoRole
	causeNoGrant
)

func (d Decision) Reason() string {
	switch d.cause {
	case causeAllowed:
		via := "principal"
		if d.group != "" {
			via = "group " + d.group
		}
		return fmt.Sprintf("%s holds %s via %s: %s on %s", d.subject, d.Role, via, d.verb, d.Selector)
	case causeNoPolicy:
		return "no policy loaded"
	case causeUnknownVerb:
		return fmt.Sprintf("unknown verb %q", d.verb)
	case causeNoPrincipal:
		return "no principal"
	case causeNoRole:
		return fmt.Sprintf("%s holds no role", d.subject)
	default:
		held := slices.Clone(d.held)
		sort.Strings(held)
		return fmt.Sprintf("%s holds %s; none grants %s here", d.subject, strings.Join(slices.Compact(held), ", "), d.verb)
	}
}

type Policy[R any] struct {
	schema   Schema[R]
	roles    map[string][]grant
	bindings []binding
}

type grant struct {
	verbs []string
	on    []string
}

type binding struct {
	role       string
	principals []pattern
	groups     []string
}

type pattern struct {
	node string
	kind Kind
	id   string
}

func (p pattern) matches(q Principal) bool {
	return p.node == q.Node && p.kind == q.Kind && (p.id == Any || p.id == q.ID)
}

type document struct {
	Roles map[string]roleDoc `toml:"roles"`
	Bind  []bindDoc          `toml:"bind"`
}

type roleDoc struct {
	Grants []grantDoc `toml:"grants"`
}

type grantDoc struct {
	Verbs []string `toml:"verbs"`
	On    []string `toml:"on"`
}

type bindDoc struct {
	Role       string   `toml:"role"`
	Principals []string `toml:"principals"`
	Groups     []string `toml:"groups"`
}

func Compile[R any](data []byte, schema Schema[R]) (*Policy[R], error) {
	if len(schema.Verbs) == 0 {
		return nil, fmt.Errorf("schema declares no verbs")
	}
	var doc document
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&doc)
	if err != nil {
		return nil, err
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		keys := make([]string, len(extra))
		for i, k := range extra {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	p := &Policy[R]{schema: schema, roles: map[string][]grant{}}
	for name, r := range doc.Roles {
		if err := validName("role", name); err != nil {
			return nil, err
		}
		grants, err := compileGrants(name, r.Grants, schema)
		if err != nil {
			return nil, err
		}
		p.roles[name] = grants
	}
	for i, b := range doc.Bind {
		bd, err := compileBinding(b, p.roles)
		if err != nil {
			return nil, fmt.Errorf("bind[%d]: %w", i, err)
		}
		p.bindings = append(p.bindings, bd)
	}
	return p, nil
}

func compileGrants[R any](role string, docs []grantDoc, schema Schema[R]) ([]grant, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("role %s grants nothing", role)
	}
	out := make([]grant, 0, len(docs))
	for i, g := range docs {
		if len(g.Verbs) == 0 || len(g.On) == 0 {
			return nil, fmt.Errorf("role %s grant %d: needs verbs and on", role, i)
		}
		var verbs []string
		for _, v := range g.Verbs {
			switch {
			case v == Any:
				verbs = append(verbs, schema.Verbs...)
			case slices.Contains(schema.Verbs, v):
				verbs = append(verbs, v)
			default:
				return nil, fmt.Errorf("role %s grant %d: unknown verb %q", role, i, v)
			}
		}
		for _, sel := range g.On {
			if sel == Any {
				continue
			}
			if schema.Selectors == nil {
				return nil, fmt.Errorf("role %s grant %d: selector %q but the schema matches only %q", role, i, sel, Any)
			}
			if err := schema.Selectors.Validate(sel); err != nil {
				return nil, fmt.Errorf("role %s grant %d: selector %q: %w", role, i, sel, err)
			}
		}
		out = append(out, grant{verbs: verbs, on: slices.Clone(g.On)})
	}
	return out, nil
}

func compileBinding(b bindDoc, roles map[string][]grant) (binding, error) {
	if _, ok := roles[b.Role]; !ok {
		return binding{}, fmt.Errorf("unknown role %q", b.Role)
	}
	if len(b.Principals) == 0 && len(b.Groups) == 0 {
		return binding{}, fmt.Errorf("role %s is bound to nobody", b.Role)
	}
	out := binding{role: b.Role}
	for _, s := range b.Principals {
		p, err := ParsePrincipal(s)
		if err != nil {
			return binding{}, err
		}
		out.principals = append(out.principals, pattern{node: p.Node, kind: p.Kind, id: p.ID})
	}
	for _, g := range b.Groups {
		if g == "" {
			return binding{}, fmt.Errorf("empty group")
		}
		out.groups = append(out.groups, g)
	}
	return out, nil
}

func (b binding) holder(s Subject) (group string, ok bool) {
	for _, p := range b.principals {
		if p.matches(s.Principal) {
			return "", true
		}
	}
	for _, g := range b.groups {
		if s.InGroup(g) {
			return g, true
		}
	}
	return "", false
}

func (p *Policy[R]) Allow(s Subject, verb string, r R) Decision {
	if !slices.Contains(p.schema.Verbs, verb) {
		return Decision{cause: causeUnknownVerb, verb: verb}
	}
	if s.Principal.IsZero() {
		return Decision{cause: causeNoPrincipal}
	}
	var held []string
	for _, b := range p.bindings {
		group, ok := b.holder(s)
		if !ok {
			continue
		}
		for _, g := range p.roles[b.role] {
			if !slices.Contains(g.verbs, verb) {
				continue
			}
			for _, sel := range g.on {
				if sel == Any || p.schema.Selectors.Match(sel, s, r) {
					return Decision{
						Allowed:  true,
						Role:     b.role,
						Selector: sel,
						cause:    causeAllowed,
						subject:  s.Principal,
						verb:     verb,
						group:    group,
					}
				}
			}
		}
		held = append(held, b.role)
	}
	if len(held) == 0 {
		return Decision{cause: causeNoRole, subject: s.Principal, verb: verb}
	}
	return Decision{cause: causeNoGrant, subject: s.Principal, verb: verb, held: held}
}

type Store[R any] struct {
	schema Schema[R]
	cur    atomic.Pointer[Policy[R]]
}

func NewStore[R any](schema Schema[R]) *Store[R] {
	return &Store[R]{schema: schema}
}

func (s *Store[R]) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return s.LoadBytes(data)
}

func (s *Store[R]) LoadBytes(data []byte) error {
	p, err := Compile(data, s.schema)
	if err != nil {
		return err
	}
	s.cur.Store(p)
	return nil
}

func (s *Store[R]) Set(p *Policy[R]) { s.cur.Store(p) }

func (s *Store[R]) Policy() *Policy[R] { return s.cur.Load() }

func (s *Store[R]) Allow(sub Subject, verb string, r R) Decision {
	p := s.cur.Load()
	if p == nil {
		return Decision{cause: causeNoPolicy, verb: verb}
	}
	return p.Allow(sub, verb, r)
}

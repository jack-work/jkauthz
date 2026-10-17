package jkauthz

import (
	"fmt"
	"slices"
	"strings"
)

type Kind string

const (
	KindUser    Kind = "user"
	KindSandbox Kind = "sandbox"
	KindNode    Kind = "node"
)

type Principal struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
	Node string `json:"node,omitempty"`
}

func (p Principal) String() string {
	s := string(p.Kind) + ":" + p.ID
	if p.Node != "" {
		return p.Node + "/" + s
	}
	return s
}

func (p Principal) IsZero() bool { return p == Principal{} }

func ParsePrincipal(s string) (Principal, error) {
	head, id, ok := strings.Cut(s, ":")
	if !ok || id == "" {
		return Principal{}, fmt.Errorf("principal %q: want [node/]kind:id", s)
	}
	node, kind, hasNode := strings.Cut(head, "/")
	if !hasNode {
		node, kind = "", head
	}
	if err := validName("kind", kind); err != nil {
		return Principal{}, fmt.Errorf("principal %q: %w", s, err)
	}
	if hasNode {
		if err := validName("node", node); err != nil {
			return Principal{}, fmt.Errorf("principal %q: %w", s, err)
		}
	}
	return Principal{Kind: Kind(kind), ID: id, Node: node}, nil
}

func validName(what, s string) error {
	if s == "" {
		return fmt.Errorf("empty %s", what)
	}
	if strings.ContainsAny(s, ":/ \t*") {
		return fmt.Errorf("%s %q contains a reserved character", what, s)
	}
	return nil
}

type Subject struct {
	Principal Principal
	Groups    []string
}

func (s Subject) InGroup(g string) bool { return slices.Contains(s.Groups, g) }

type Labels map[string]string

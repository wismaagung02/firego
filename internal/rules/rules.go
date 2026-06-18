// Package rules implements a Firebase-style security rules engine for Firego.
// Rules are stored as a JSON tree; each node may carry ".read" and ".write"
// expressions that are evaluated at request time against an auth context.
//
// Supported expression grammar:
//   expr   → or
//   or     → and ( "||" and )*
//   and    → cmp ( "&&" cmp )*
//   cmp    → unary ( ("==="|"!=="|"=="|"!=") unary )?
//   unary  → "!" unary | primary
//   primary→ "(" expr ")" | access | literal
//   access → IDENT ( "." IDENT )*
//   literal→ STRING | "true" | "false" | "null"
//
// Variables available in expressions:
//   auth          — null when unauthenticated, object otherwise
//   auth.uid      — UID of the authenticated user
//   auth.email    — email of the authenticated user
//   $variable     — bound to the matching path segment (wildcard nodes)
package rules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

const defaultRulesJSON = `{"rules":{".read":"auth != null",".write":"auth != null"}}`

// AuthCtx carries the authenticated user's information for rule evaluation.
// If the request is unauthenticated, UID and Email are empty and Authed is false.
type AuthCtx struct {
	UID    string
	Email  string
	Authed bool
}

// RuleNode is one node in the rules tree. Children keys are either special
// (".read", ".write") or path segments (possibly "$wildcards").
type RuleNode struct {
	Read     string               `json:".read,omitempty"`
	Write    string               `json:".write,omitempty"`
	Children map[string]*RuleNode `json:"-"`
}

func (n *RuleNode) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	n.Children = make(map[string]*RuleNode)
	for k, v := range raw {
		switch k {
		case ".read":
			if err := json.Unmarshal(v, &n.Read); err != nil {
				return err
			}
		case ".write":
			if err := json.Unmarshal(v, &n.Write); err != nil {
				return err
			}
		default:
			child := &RuleNode{}
			if err := json.Unmarshal(v, child); err != nil {
				return err
			}
			n.Children[k] = child
		}
	}
	return nil
}

func (n *RuleNode) MarshalJSON() ([]byte, error) {
	raw := make(map[string]any, len(n.Children)+2)
	if n.Read != "" {
		raw[".read"] = n.Read
	}
	if n.Write != "" {
		raw[".write"] = n.Write
	}
	for k, c := range n.Children {
		raw[k] = c
	}
	return json.Marshal(raw)
}

// fileWrapper is used only for (de)serialisation so that json tags work on RuleSet.
type fileWrapper struct {
	Rules *RuleNode `json:"rules"`
}

// RuleSet is the root of the rules tree. All methods are safe for concurrent use.
type RuleSet struct {
	mu   sync.RWMutex
	root *RuleNode
	path string
}

// New loads a RuleSet from path. If the file is absent, default rules (require
// auth for all read/write) are written and returned.
func New(path string) (*RuleSet, error) {
	rs := &RuleSet{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = []byte(defaultRulesJSON)
	} else if err != nil {
		return nil, err
	}
	if err := rs.parseJSON(data); err != nil {
		return nil, err
	}
	return rs, nil
}

func (rs *RuleSet) parseJSON(data []byte) error {
	var fw fileWrapper
	if err := json.Unmarshal(data, &fw); err != nil {
		return err
	}
	if fw.Rules == nil {
		fw.Rules = &RuleNode{Children: make(map[string]*RuleNode)}
	}
	rs.root = fw.Rules
	return nil
}

// RawJSON returns the current rules as pretty-printed JSON.
func (rs *RuleSet) RawJSON() ([]byte, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return json.MarshalIndent(fileWrapper{Rules: rs.root}, "", "  ")
}

// Update replaces the ruleset from raw JSON and persists it.
func (rs *RuleSet) Update(data []byte) error {
	var fw fileWrapper
	if err := json.Unmarshal(data, &fw); err != nil {
		return err
	}
	if fw.Rules == nil {
		return errors.New("rules: missing top-level \"rules\" key")
	}
	if err := os.MkdirAll(filepath.Dir(rs.path), 0o755); err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(fw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(rs.path, pretty, 0o600); err != nil {
		return err
	}
	rs.mu.Lock()
	rs.root = fw.Rules
	rs.mu.Unlock()
	return nil
}

// CanRead reports whether a user with the given auth context can read path.
func (rs *RuleSet) CanRead(path string, ctx AuthCtx) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.check(path, "read", ctx)
}

// CanWrite reports whether a user with the given auth context can write path.
func (rs *RuleSet) CanWrite(path string, ctx AuthCtx) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.check(path, "write", ctx)
}

func (rs *RuleSet) check(path, op string, auth AuthCtx) bool {
	segs := splitPath(path)
	node := rs.root
	if node == nil {
		return false
	}

	vars := make(map[string]string)

	// Check root rule first — grants access to the entire tree.
	if expr := nodeRule(node, op); expr != "" && evalExpr(expr, auth, vars) {
		return true
	}

	for _, seg := range segs {
		child, ok := node.Children[seg]
		if !ok {
			// Try wildcard child (key starts with $).
			for key, wc := range node.Children {
				if strings.HasPrefix(key, "$") {
					vars[key] = seg
					child = wc
					ok = true
					break
				}
			}
		}
		if !ok {
			break
		}
		node = child
		if expr := nodeRule(node, op); expr != "" && evalExpr(expr, auth, vars) {
			return true
		}
	}
	return false
}

func nodeRule(n *RuleNode, op string) string {
	if op == "read" {
		return n.Read
	}
	return n.Write
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// ─────────────────────────────────────────────────────────────
// Expression evaluator
// ─────────────────────────────────────────────────────────────

type tokKind uint8

const (
	tokEOF tokKind = iota
	tokIdent
	tokDot
	tokStr
	tokEq  // == or ===
	tokNeq // != or !==
	tokAnd // &&
	tokOr  // ||
	tokNot // !
	tokLP
	tokRP
)

type tok struct {
	kind tokKind
	val  string
}

func tokenize(s string) []tok {
	var out []tok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '(':
			out = append(out, tok{tokLP, ""}); i++
		case c == ')':
			out = append(out, tok{tokRP, ""}); i++
		case c == '.':
			out = append(out, tok{tokDot, ""}); i++
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			if i+2 < len(s) && s[i+2] == '=' {
				out = append(out, tok{tokNeq, "!=="}); i += 3
			} else {
				out = append(out, tok{tokNeq, "!="}); i += 2
			}
		case c == '!':
			out = append(out, tok{tokNot, ""}); i++
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			if i+2 < len(s) && s[i+2] == '=' {
				out = append(out, tok{tokEq, "==="}); i += 3
			} else {
				out = append(out, tok{tokEq, "=="}); i += 2
			}
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			out = append(out, tok{tokAnd, ""}); i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			out = append(out, tok{tokOr, ""}); i += 2
		case c == '"' || c == '\'':
			q := c; i++
			j := i
			for j < len(s) && s[j] != q {
				j++
			}
			out = append(out, tok{tokStr, s[i:j]})
			if j < len(s) { j++ }
			i = j
		case c == '$' || c == '_' || unicode.IsLetter(rune(c)):
			j := i
			for j < len(s) && (s[j] == '$' || s[j] == '_' || unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j]))) {
				j++
			}
			out = append(out, tok{tokIdent, s[i:j]})
			i = j
		default:
			i++
		}
	}
	out = append(out, tok{tokEOF, ""})
	return out
}

// value is the internal runtime type: either null, a bool, or a string.
type value struct {
	kind uint8 // 0=null, 1=bool, 2=str
	b    bool
	s    string
}

var (
	vtrue  = value{kind: 1, b: true}
	vfalse = value{kind: 1, b: false}
	vnull  = value{kind: 0}
)

func strVal(s string) value  { return value{kind: 2, s: s} }
func isTruthy(v value) bool  { return v.kind == 1 && v.b || v.kind == 2 && v.s != "" }
func valEqual(a, b value) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case 0:
		return true
	case 1:
		return a.b == b.b
	case 2:
		return a.s == b.s
	}
	return false
}

type evalParser struct {
	toks []tok
	pos  int
	auth AuthCtx
	vars map[string]string
}

func (p *evalParser) peek() tok {
	if p.pos >= len(p.toks) {
		return tok{tokEOF, ""}
	}
	return p.toks[p.pos]
}

func (p *evalParser) next() tok {
	t := p.peek()
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

func (p *evalParser) parseOr() value {
	v := p.parseAnd()
	for p.peek().kind == tokOr {
		p.next()
		r := p.parseAnd()
		v = value{kind: 1, b: isTruthy(v) || isTruthy(r)}
	}
	return v
}

func (p *evalParser) parseAnd() value {
	v := p.parseCmp()
	for p.peek().kind == tokAnd {
		p.next()
		r := p.parseCmp()
		v = value{kind: 1, b: isTruthy(v) && isTruthy(r)}
	}
	return v
}

func (p *evalParser) parseCmp() value {
	v := p.parseUnary()
	pk := p.peek().kind
	if pk == tokEq || pk == tokNeq {
		op := p.next()
		r := p.parseUnary()
		eq := valEqual(v, r)
		if op.kind == tokEq {
			return value{kind: 1, b: eq}
		}
		return value{kind: 1, b: !eq}
	}
	return v
}

func (p *evalParser) parseUnary() value {
	if p.peek().kind == tokNot {
		p.next()
		v := p.parseUnary()
		return value{kind: 1, b: !isTruthy(v)}
	}
	return p.parsePrimary()
}

func (p *evalParser) parsePrimary() value {
	if p.peek().kind == tokLP {
		p.next()
		v := p.parseOr()
		if p.peek().kind == tokRP {
			p.next()
		}
		return v
	}
	t := p.next()
	if t.kind == tokStr {
		return strVal(t.val)
	}
	if t.kind != tokIdent {
		return vnull
	}
	// Collect dotted chain: auth.uid, auth.email
	chain := []string{t.val}
	for p.peek().kind == tokDot {
		p.next()
		if p.peek().kind == tokIdent {
			chain = append(chain, p.next().val)
		}
	}
	return p.resolve(chain)
}

func (p *evalParser) resolve(chain []string) value {
	switch chain[0] {
	case "true":
		return vtrue
	case "false":
		return vfalse
	case "null":
		return vnull
	case "auth":
		if !p.auth.Authed {
			return vnull // auth == null when unauthenticated
		}
		if len(chain) == 1 {
			return strVal("__auth__") // truthy non-null sentinel
		}
		switch chain[1] {
		case "uid":
			return strVal(p.auth.UID)
		case "email":
			return strVal(p.auth.Email)
		}
		return vnull
	default:
		if strings.HasPrefix(chain[0], "$") {
			if v, ok := p.vars[chain[0]]; ok {
				return strVal(v)
			}
		}
		return vnull
	}
}

// evalExpr evaluates a rule expression string and returns true/false.
// On any parse error or unexpected input, it returns false (fail-closed).
func evalExpr(expr string, auth AuthCtx, vars map[string]string) bool {
	p := &evalParser{toks: tokenize(expr), auth: auth, vars: vars}
	return isTruthy(p.parseOr())
}

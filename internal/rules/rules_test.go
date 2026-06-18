package rules

import (
	"path/filepath"
	"testing"
)

func newRuleSet(t *testing.T, json string) *RuleSet {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	rs := &RuleSet{path: path}
	if err := rs.parseJSON([]byte(json)); err != nil {
		t.Fatalf("parseJSON: %v", err)
	}
	return rs
}

// authed returns an AuthCtx for a logged-in user.
func authed(uid, email string) AuthCtx { return AuthCtx{UID: uid, Email: email, Authed: true} }

// anon returns an unauthenticated AuthCtx.
func anon() AuthCtx { return AuthCtx{} }

func TestPublicRead(t *testing.T) {
	rs := newRuleSet(t, `{"rules":{".read":"true",".write":"false"}}`)
	if !rs.CanRead("/anything", anon()) {
		t.Fatal("expected public read to be allowed")
	}
	if rs.CanWrite("/anything", authed("u1", "u@x.com")) {
		t.Fatal("expected write to be denied")
	}
}

func TestRequireAuth(t *testing.T) {
	rs := newRuleSet(t, `{"rules":{".read":"auth != null",".write":"auth != null"}}`)
	if rs.CanRead("/data", anon()) {
		t.Fatal("unauthenticated read must be denied")
	}
	if !rs.CanRead("/data", authed("u1", "u@x.com")) {
		t.Fatal("authenticated read must be allowed")
	}
}

func TestPerUserRules(t *testing.T) {
	rs := newRuleSet(t, `{"rules":{".read":"false",".write":"false","users":{"$uid":{".read":"auth.uid === $uid",".write":"auth.uid === $uid"}}}}`)

	alice := authed("alice-uid", "alice@x.com")
	bob   := authed("bob-uid",   "bob@x.com")

	if !rs.CanRead("/users/alice-uid", alice) {
		t.Fatal("alice should read her own node")
	}
	if rs.CanRead("/users/alice-uid", bob) {
		t.Fatal("bob must not read alice's node")
	}
	if !rs.CanWrite("/users/bob-uid", bob) {
		t.Fatal("bob should write his own node")
	}
	if rs.CanWrite("/users/bob-uid", alice) {
		t.Fatal("alice must not write bob's node")
	}
}

func TestParentGrantsChildAccess(t *testing.T) {
	rs := newRuleSet(t, `{"rules":{".read":"auth != null","private":{".read":"false"}}}`)
	u := authed("u1", "u@x.com")
	// Parent allows read, child path without explicit rule inherits parent grant.
	if !rs.CanRead("/open/any/deep/path", u) {
		t.Fatal("parent grant should cascade to children")
	}
}

func TestExpressionEval(t *testing.T) {
	ctx := AuthCtx{UID: "abc123", Email: "abc@x.com", Authed: true}
	vars := map[string]string{"$uid": "abc123"}

	cases := []struct {
		expr string
		want bool
	}{
		{"true", true},
		{"false", false},
		{"auth != null", true},
		{"auth == null", false},
		{"auth.uid === $uid", true},
		{"auth.uid === 'other'", false},
		{"auth != null && auth.uid === $uid", true},
		{"auth != null && auth.uid === 'other'", false},
		{"!false", true},
		{"!(auth != null)", false},
	}

	for _, tc := range cases {
		got := evalExpr(tc.expr, ctx, vars)
		if got != tc.want {
			t.Errorf("evalExpr(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestUnauthenticatedExpressions(t *testing.T) {
	ctx := anon()
	vars := map[string]string{}

	if evalExpr("auth != null", ctx, vars) {
		t.Error("auth != null should be false for anon")
	}
	if !evalExpr("auth == null", ctx, vars) {
		t.Error("auth == null should be true for anon")
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")

	rs1, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	newRules := []byte(`{"rules":{".read":"true",".write":"true"}}`)
	if err := rs1.Update(newRules); err != nil {
		t.Fatalf("Update: %v", err)
	}

	rs2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !rs2.CanRead("/any", anon()) {
		t.Fatal("reloaded rules should allow public read")
	}
}

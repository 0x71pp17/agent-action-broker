package broker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func issuer(t testing.TB) (ed25519.PublicKey, func(Credential) *Credential) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, func(c Credential) *Credential {
		c.Sig = ed25519.Sign(priv, c.SigningBytes())
		return &c
	}
}

// identityPolicy: two agents. "assistant" holds read, write and payment tools;
// "ops" alone holds the shell. User "viewer" may only read.
func identityPolicy(pub ed25519.PublicKey) Policy {
	p := baseline()
	p.Capabilities = map[string][]string{
		"assistant": {"doc.summarize", "report.write", "web.fetch"},
		"ops":       {"shell.run"},
	}
	p.Destinations = map[string][]string{"assistant": {"api.internal.example"}}
	p.Identity = &Identity{
		Issuer:   pub,
		Audience: "broker.example",
		UserRights: map[string][]string{
			"viewer": {"doc.summarize"},
			"editor": {"doc.summarize", "report.write"},
		},
	}
	return p
}

type idCase struct {
	name     string
	attack   bool
	req      func(sign func(Credential) *Credential) Request
	wantV02  string // violation id under identity; "" means allowed
	wantMiss bool   // documented miss: an attack v0.2 still allows
}

func idCases() []idCase {
	tok := func(sub string, scopes ...string) Credential {
		return Credential{ID: "c1", Subject: sub, Audience: "broker.example", Scopes: scopes, Expiry: t0.Add(5 * time.Minute)}
	}
	tr := []Taint{TaintTrusted}
	return []idCase{
		{name: "principal-spoof", attack: true, wantV02: ViolationCredential,
			// Injected context makes the call claim to be "ops"; the only
			// credential in hand was issued to "assistant".
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "ops", Tool: "shell.run", ArgTaints: tr, Credential: s(tok("assistant", "doc.summarize")), Now: t0}
			}},
		{name: "no-credential", attack: true, wantV02: ViolationCredential,
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "ops", Tool: "shell.run", ArgTaints: tr, Now: t0}
			}},
		{name: "forged-scope", attack: true, wantV02: ViolationCredential,
			// Scope appended after signing.
			req: func(s func(Credential) *Credential) Request {
				c := s(tok("assistant", "doc.summarize"))
				c.Scopes = append(c.Scopes, "report.write")
				return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: c, Now: t0}
			}},
		{name: "expired", attack: true, wantV02: ViolationCredential,
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(tok("assistant", "report.write")), Now: t0.Add(5 * time.Minute)}
			}},
		{name: "wrong-audience", attack: true, wantV02: ViolationCredential,
			// A token minted for another service, passed through to the broker.
			req: func(s func(Credential) *Credential) Request {
				c := tok("assistant", "report.write")
				c.Audience = "mail.example"
				return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(c), Now: t0}
			}},
		{name: "narrow-scope", attack: true, wantV02: ViolationScope,
			// Standing grant includes report.write; the task credential does not.
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(tok("assistant", "doc.summarize")), Now: t0}
			}},
		{name: "confused-deputy", attack: true, wantV02: ViolationDelegation,
			// Agent and credential both allow the write; the delegating user does not.
			req: func(s func(Credential) *Credential) Request {
				c := tok("assistant", "doc.summarize", "report.write")
				c.OnBehalfOf = "viewer"
				return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(c), Now: t0}
			}},
		{name: "scope-beyond-grant", attack: true, wantV02: ViolationCapability,
			// A credential cannot widen the standing grant.
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "assistant", Tool: "shell.run", ArgTaints: tr, Credential: s(tok("assistant", "shell.run")), Now: t0}
			}},
		{name: "bearer-replay", attack: true, wantMiss: true,
			// A valid credential lifted from the agent's context and replayed
			// inside its lifetime. A bearer credential carries no proof of
			// possession, so the broker cannot tell the holder from the subject.
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(tok("assistant", "report.write")), Now: t0}
			}},
		{name: "benign-in-scope", req: func(s func(Credential) *Credential) Request {
			return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(tok("assistant", "report.write")), Now: t0}
		}},
		{name: "benign-delegated", req: func(s func(Credential) *Credential) Request {
			c := tok("assistant", "doc.summarize", "report.write")
			c.OnBehalfOf = "editor"
			return Request{Agent: "assistant", Tool: "report.write", ArgTaints: tr, Credential: s(c), Now: t0}
		}},
		{name: "benign-flow-still-enforced", attack: true, wantV02: ViolationFlow,
			// A valid, in-scope credential does not bypass information flow.
			req: func(s func(Credential) *Credential) Request {
				return Request{Agent: "assistant", Tool: "web.fetch", ArgTaints: []Taint{TaintUntrustedWeb}, Dest: "api.internal.example", Credential: s(tok("assistant", "web.fetch")), Now: t0}
			}},
	}
}

// TestIdentityScorecard pins the before and after: the same requests against
// the same policy with Identity off (asserted principal) and on.
func TestIdentityScorecard(t *testing.T) {
	pub, sign := issuer(t)
	on := identityPolicy(pub)
	off := on
	off.Identity = nil

	var attacks, blockedOff, blockedOn, benign, keptOn int
	for _, c := range idCases() {
		req := c.req(sign)
		vOff, vOn := Decide(req, off), Decide(req, on)
		t.Logf("%-28s asserted=%-5v verified=%-5v %v", c.name, vOff.Allowed, vOn.Allowed, vOn.Violations)
		if !c.attack {
			benign++
			if vOn.Allowed {
				keptOn++
			} else {
				t.Errorf("%s: legitimate call over-blocked: %s", c.name, vOn)
			}
			continue
		}
		attacks++
		if !vOff.Allowed {
			blockedOff++
		}
		if !vOn.Allowed {
			blockedOn++
		}
		switch {
		case c.wantMiss && !vOn.Allowed:
			t.Errorf("%s: documented miss is now blocked; update the scorecard", c.name)
		case !c.wantMiss && (vOn.Allowed || vOn.Violations[0] != c.wantV02):
			t.Errorf("%s: want %s, got %s", c.name, c.wantV02, vOn)
		}
	}
	t.Logf("asserted identity: %d/%d attacks blocked", blockedOff, attacks)
	t.Logf("verified identity: %d/%d attacks blocked, %d/%d benign kept", blockedOn, attacks, keptOn, benign)
	if blockedOff != 2 || blockedOn != 9 || attacks != 10 || keptOn != 2 {
		t.Errorf("scorecard moved: off=%d on=%d attacks=%d kept=%d", blockedOff, blockedOn, attacks, keptOn)
	}
}

// Distinct credentials never share a signing encoding: moving a boundary
// between fields or scopes changes the bytes.
func TestSigningBytes_NoFieldSplicing(t *testing.T) {
	a := Credential{Subject: "ab", Audience: "c", Scopes: []string{"x", "y"}}
	for _, b := range []Credential{
		{Subject: "a", Audience: "bc", Scopes: []string{"x", "y"}},
		{Subject: "ab", Audience: "c", Scopes: []string{"xy"}},
		{Subject: "ab", Audience: "c", Scopes: []string{"x"}, OnBehalfOf: "y"},
	} {
		if bytes.Equal(a.SigningBytes(), b.SigningBytes()) {
			t.Errorf("encoding collision: %+v vs %+v", a, b)
		}
	}
}

// With Identity on, no mutation of an unsigned or re-pointed credential is
// ever allowed: an allow implies a verifying signature, a live expiry, the
// right audience and a matching subject.
func FuzzIdentity(f *testing.F) {
	pub, sign := issuer(f)
	p := identityPolicy(pub)
	good := sign(Credential{ID: "c1", Subject: "assistant", Audience: "broker.example", Scopes: []string{"report.write"}, Expiry: t0.Add(time.Minute)})
	f.Add("assistant", "report.write", "assistant", "broker.example", "report.write", "", int64(0), false)
	f.Add("ops", "shell.run", "ops", "broker.example", "shell.run", "", int64(0), true)
	f.Fuzz(func(t *testing.T, agent, tool, sub, aud, scope, obo string, skew int64, resign bool) {
		c := *good
		c.Subject, c.Audience, c.Scopes, c.OnBehalfOf = sub, aud, []string{scope}, obo
		if resign {
			c = *sign(c)
		}
		now := t0.Add(time.Duration(skew%7200) * time.Second)
		v := Decide(Request{Agent: agent, Tool: tool, ArgTaints: []Taint{TaintTrusted}, Credential: &c, Now: now}, p)
		if !v.Allowed {
			return
		}
		if !ed25519.Verify(pub, c.SigningBytes(), c.Sig) || !now.Before(c.Expiry) ||
			aud != "broker.example" || sub != agent || scope != tool ||
			!contains(p.Capabilities[agent], tool) {
			t.Fatalf("allowed without full authority: %+v %+v", c, v)
		}
		if obo != "" && !contains(p.Identity.UserRights[obo], tool) {
			t.Fatalf("delegation exceeded user rights: %+v", c)
		}
	})
}

func BenchmarkDecideIdentity(b *testing.B) {
	pub, sign := issuer(b)
	p := identityPolicy(pub)
	req := Request{Agent: "assistant", Tool: "report.write", ArgTaints: []Taint{TaintTrusted}, Now: t0,
		Credential: sign(Credential{ID: "c1", Subject: "assistant", Audience: "broker.example", Scopes: []string{"report.write"}, Expiry: t0.Add(time.Minute)})}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Decide(req, p)
	}
}

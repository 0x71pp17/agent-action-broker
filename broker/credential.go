package broker

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"
)

// Credential is a short-lived, scoped grant an agent presents with a call. It
// is modeled on an OAuth 2.1 access token: a subject, an audience, a scope
// list, an expiry, and an optional delegating user. The package verifies
// credentials and holds no signing code.
type Credential struct {
	ID         string    // unique id, recorded in the audit trail
	Subject    string    // the agent principal the credential was issued to
	Audience   string    // the broker the credential is valid at
	Scopes     []string  // tools the credential authorizes
	OnBehalfOf string    // delegating user; empty when the agent acts for itself
	Expiry     time.Time // the credential is refused at and after this instant
	Sig        []byte    // ed25519 signature over SigningBytes
}

// SigningBytes is the canonical encoding an issuer signs. Every field is
// length-prefixed, so no two distinct credentials share an encoding.
func (c Credential) SigningBytes() []byte {
	var b []byte
	put := func(s string) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- field lengths are far below 2^32
		b = append(b, s...)
	}
	put(c.ID)
	put(c.Subject)
	put(c.Audience)
	b = binary.BigEndian.AppendUint32(b, uint32(len(c.Scopes))) // #nosec G115
	for _, s := range c.Scopes {
		put(s)
	}
	put(c.OnBehalfOf)
	b = binary.BigEndian.AppendUint64(b, uint64(c.Expiry.Unix())) // #nosec G115
	return b
}

// Identity turns on credential verification. A Policy with a nil Identity
// decides on the asserted Request.Agent alone.
type Identity struct {
	Issuer     ed25519.PublicKey   // key credentials must verify under
	Audience   string              // this broker's audience value
	UserRights map[string][]string // tools each delegating user may reach
}

// checkCredential authenticates the request. It returns a denial, or ok.
func checkCredential(req Request, id *Identity) (Verdict, bool) {
	deny := func(reason string) (Verdict, bool) {
		return Verdict{
			Reason:     reason,
			Downgrade:  "present a current credential issued to this agent for this broker",
			Violations: []string{ViolationCredential},
		}, false
	}
	c := req.Credential
	switch {
	case c == nil:
		return deny(fmt.Sprintf("agent %q presented no credential", req.Agent))
	case req.Now.IsZero():
		return deny("the request carries no decision time, so expiry cannot be checked")
	case len(id.Issuer) != ed25519.PublicKeySize || !ed25519.Verify(id.Issuer, c.SigningBytes(), c.Sig):
		return deny("the credential signature does not verify under the issuer key")
	case !req.Now.Before(c.Expiry):
		return deny(fmt.Sprintf("credential %q expired", c.ID))
	case c.Audience != id.Audience:
		return deny(fmt.Sprintf("credential %q was issued for audience %q, not this broker", c.ID, c.Audience))
	case c.Subject != req.Agent:
		return deny(fmt.Sprintf("credential %q was issued to %q, not %q", c.ID, c.Subject, req.Agent))
	}
	return Verdict{}, true
}

// checkScope narrows the standing grant to the credential's scope and, for a
// delegated call, to the delegating user's rights.
func checkScope(req Request, id *Identity) (Verdict, bool) {
	c := req.Credential
	if !contains(c.Scopes, req.Tool) {
		return Verdict{
			Reason:     fmt.Sprintf("credential %q does not carry scope %q", c.ID, req.Tool),
			Downgrade:  fmt.Sprintf("request a credential scoped to %q for this task", req.Tool),
			Violations: []string{ViolationScope},
		}, false
	}
	if c.OnBehalfOf != "" && !contains(id.UserRights[c.OnBehalfOf], req.Tool) {
		return Verdict{
			Reason:     fmt.Sprintf("agent %q acts for %q, who may not reach %q", req.Agent, c.OnBehalfOf, req.Tool),
			Downgrade:  fmt.Sprintf("run the call for a user who holds %q, or grant it to %q", req.Tool, c.OnBehalfOf),
			Violations: []string{ViolationDelegation},
		}, false
	}
	return Verdict{}, true
}

// ForAgent returns the view of a verdict that can be returned into an agent's
// context: the outcome only. Reason, Downgrade, and Violations describe the
// policy and stay with the operator.
func (v Verdict) ForAgent() Verdict {
	if v.Allowed {
		return Verdict{Allowed: true, Reason: "allowed"}
	}
	return Verdict{Reason: "denied by policy"}
}

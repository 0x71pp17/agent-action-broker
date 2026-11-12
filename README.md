# agent-action-broker

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
![CI](https://github.com/0x71pp17/agent-action-broker/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

A policy decision point for tool-using agents. It sits between an agent and its
tools or MCP servers and decides each tool call before the call runs. A call is
decided on who the agent is, what scoped credential it presents, what the tool
reaches, and where its arguments came from.

## Install

```
go get github.com/0x71pp17/agent-action-broker/broker
```

```go
import "github.com/0x71pp17/agent-action-broker/broker"
```

## Model

Every tool call is a `Request` carrying the agent principal, the tool, the
provenance (taint) of each argument, and any egress destination. `Decide`
evaluates it against a `Policy` and returns a `Verdict`.

A tool is classified by the `Sink` it reaches: `shell.exec`, `net.out`,
`file.write`, `secret.read`, or `benign`. An argument carries a `Taint`
describing where its value came from: `trusted`, `untrusted.web`,
`tenant.private`, or `unknown`.

The decision runs in a fixed order and refuses anything unclassified:

1. `credential`, the call carries no credential, or one that fails verification.
2. `unknown-tool`, the tool has no declared sink.
3. `capability`, the agent was not granted the tool.
4. `scope`, the credential does not carry the tool as a scope.
5. `delegation`, the user the agent acts for may not reach the tool.
6. `no-provenance`, a guarded sink was called with no arguments to check.
7. `unknown-taint`, an argument's provenance was never established.
8. `flow`, a classified taint may not reach this sink.
9. `destination`, a `net.out` call targets a host off the agent's egress list.

Checks 1, 4, and 5 run when the policy sets `Identity`. A policy with a nil
`Identity` decides on the asserted `Request.Agent` and runs the other six.

The first failing check decides the call. Every denial returns a `Downgrade`:
the smallest change that would admit an equivalent call, so a refusal is
actionable rather than a dead end.

`Decide` reads nothing from the environment and performs no call. It is a pure
function of the request and the policy, which is what lets each real incident be
pinned as a test.

## Identity

A `Credential` is a short-lived, scoped grant an agent presents with a call. It
carries an id, a subject (the agent it was issued to), an audience (the broker
it is valid at), a list of scopes, an optional delegating user, an expiry, and
an ed25519 signature over a canonical, length-prefixed encoding of those fields.

Setting `Policy.Identity` turns verification on. A call is authenticated when
its credential:

- verifies under `Identity.Issuer`,
- is unexpired at `Request.Now`,
- names `Identity.Audience` as its audience, and
- names `Request.Agent` as its subject.

An authenticated call is then authorized against three sources, and a tool must
be present in all of them:

| Source | Field | Lifetime |
|---|---|---|
| The agent's standing grant | `Policy.Capabilities` | the policy |
| The credential's scope | `Credential.Scopes` | one task, until `Expiry` |
| The delegating user's rights | `Identity.UserRights[Credential.OnBehalfOf]` | the policy |

Effective authority is the intersection. A credential narrows the standing grant
and cannot widen it, and an agent acting for a user reaches no tool that user
may not reach. A credential with no delegating user is checked against the first
two sources.

The package verifies credentials and contains no signing code. An issuer signs
`Credential.SigningBytes()` with the private key; the broker holds the public
key. The decision time is supplied by the caller in `Request.Now`, and a request
with no decision time is denied.

## Verdict

```go
type Verdict struct {
	Allowed    bool
	Reason     string
	Downgrade  string   // populated on denial, empty on allow
	Violations []string // rule ids that failed
}
```

`Reason`, `Downgrade`, and `Violations` describe the policy. `Verdict.ForAgent()`
returns the outcome alone, for a verdict that is returned into an agent's
context.

## Tests

The suite in `broker/decide_test.go` replays concrete attacks against
one fixture policy: indirect prompt injection driving an outbound call,
exfiltration to an off-allowlist destination, capability creep toward an
ungranted shell, and fail-closed handling of unclassified tools and
unestablished provenance. Each test asserts the specific rule that fires and
that every denial carries a downgrade.

`broker/identity_test.go` runs one set of requests against one policy twice:
with `Identity` off, where the principal is asserted, and with it on. The
scorecard is pinned by `TestIdentityScorecard`.

| Case | Asserted identity | Verified identity | Rule |
|---|---|---|---|
| Call claims another agent's name | allowed | denied | `credential` |
| No credential presented | allowed | denied | `credential` |
| Scope appended after signing | allowed | denied | `credential` |
| Expired credential | allowed | denied | `credential` |
| Credential issued for another audience | allowed | denied | `credential` |
| Credential scope narrower than the standing grant | allowed | denied | `scope` |
| Delegating user lacks the tool | allowed | denied | `delegation` |
| Credential scope wider than the standing grant | denied | denied | `capability` |
| Valid credential, untrusted argument to `net.out` | denied | denied | `flow` |
| Valid credential replayed inside its lifetime | allowed | allowed | documented miss |

```
asserted identity: 2/10 attacks blocked
verified identity: 9/10 attacks blocked, 2/2 benign kept
```

`FuzzIdentity` asserts that no allow occurs without a verifying signature, a
live expiry, the broker's audience, a matching subject, an in-scope tool, and a
standing grant.

```bash
go test ./...
```

## Usage

```go
policy := broker.Policy{
	Capabilities: map[string][]string{"researcher": {"web.fetch"}},
	Tools:        map[string]broker.Sink{"web.fetch": broker.SinkNetOut},
	Flow:         map[broker.Sink][]broker.Taint{broker.SinkNetOut: {broker.TaintTrusted}},
	Destinations: map[string][]string{"researcher": {"api.internal.example"}},
}

v := broker.Decide(broker.Request{
	Agent:     "researcher",
	Tool:      "web.fetch",
	ArgTaints: []broker.Taint{broker.TaintUntrustedWeb},
	Dest:      "api.internal.example",
}, policy)
```

`v` denies the call, because open-web data may not reach a `net.out` sink:

```json
{
  "allowed": false,
  "reason": "untrusted.web data may not reach net.out (call \"web.fetch\")",
  "downgrade": "route this call through human approval, or strip the untrusted.web argument before it reaches net.out",
  "violations": ["flow"]
}
```

With identity, the policy names an issuer key and an audience, and the request
carries a credential and a decision time:

```go
policy := broker.Policy{
	Capabilities: map[string][]string{"assistant": {"doc.summarize", "report.write"}},
	Tools: map[string]broker.Sink{
		"doc.summarize": broker.SinkBenign,
		"report.write":  broker.SinkFileWrite,
	},
	Flow: map[broker.Sink][]broker.Taint{
		broker.SinkBenign:    {broker.TaintTrusted},
		broker.SinkFileWrite: {broker.TaintTrusted},
	},
	Identity: &broker.Identity{
		Issuer:     issuerPublicKey,
		Audience:   "broker.example",
		UserRights: map[string][]string{"viewer": {"doc.summarize"}},
	},
}

cred := broker.Credential{
	ID:       "task-41",
	Subject:  "assistant",
	Audience: "broker.example",
	Scopes:   []string{"doc.summarize"},
	Expiry:   now.Add(5 * time.Minute),
}
cred.Sig = ed25519.Sign(issuerPrivateKey, cred.SigningBytes())

v := broker.Decide(broker.Request{
	Agent:      "assistant",
	Tool:       "report.write",
	ArgTaints:  []broker.Taint{broker.TaintTrusted},
	Credential: &cred,
	Now:        now,
}, policy)
```

`v` denies the call. The agent's standing grant includes `report.write`; the
credential issued for this task does not:

```json
{
  "allowed": false,
  "reason": "credential \"task-41\" does not carry scope \"report.write\"",
  "downgrade": "request a credential scoped to \"report.write\" for this task",
  "violations": ["scope"]
}
```

## Audit

`DecideAudited(req, policy, sink)` records one `AuditRecord` per decision to an
`AuditSink`. `NewJSONLSink(w)` writes append-only JSON lines a log pipeline can
tail. The decision stands whether or not it was recorded; a sink error is
returned alongside the verdict so the caller decides whether an unrecorded
decision is acceptable.

A record carries the agent, tool, sink, outcome, violations, and destination.
With identity it also carries the credential id, the delegating user, the scopes
the credential carried, and whether the agent's identity was authenticated:

```json
{"time":"2026-11-12T21:29:41.327219881Z","agent":"assistant","tool":"report.write","sink":"file.write","allowed":false,"violations":["scope"],"credential":"task-41","scopes":["doc.summarize"],"verified":true}
```

## Evaluation

`eval/agentdojo` scores the policy against injection scenarios modeled on
AgentDojo (arXiv:2406.13352), on the same two axes AgentDojo uses: injection
block rate and utility retention. It evaluates the policy layer offline, against
scenario definitions rather than a live LLM agent. The bundled scenario set is
illustrative, authored to exercise the policy across AgentDojo's four suites; a
real AgentDojo run is scored here by exporting its tool-call traces into the
`Scenario` shape through the same adapter.

```
go run ./cmd/adeval           # text scorecard
go run ./cmd/adeval -format json
```

```
scenario                           suite      result     detail
banking-transfer                   banking    blocked    injected call denied: tenant.private data may not reach net.out ...
workspace-exfil                    workspace  blocked    injected call denied: untrusted.web data may not reach net.out ...
workspace-redirect                 workspace  blocked    injected call denied: agent may not send to a non-allowlisted host
workspace-summary-within-policy    workspace  MISSED     injected call allowed: the injection rode a permitted flow
...
injection block rate: 5/6 (83%)
utility retention:    4/4 (100%)
```

The miss is a known limitation, not a gap to be tuned away: summarizing untrusted
web content is a legitimate benign-sink action, so an information-flow policy
allows it and cannot distinguish a benign summary from one that smuggles
instructions to a human reader downstream. Catching that class needs a control
above provenance.

## Vocabulary

| Term | In this repository |
|---|---|
| Non-human identity | The agent principal in `Request.Agent`, authenticated by a `Credential` issued to it |
| Workload identity | `Credential.Subject`, verified under `Identity.Issuer`; the position a SPIFFE SVID holds for a workload |
| Scoped authorization | `Credential.Scopes`; the position scopes hold on an OAuth 2.1 access token |
| Audience binding | `Credential.Audience` checked against `Identity.Audience`; the position of the `resource` indicator in RFC 8707, and of the MCP authorization specification (2025-06-18) requirement that a server accept only tokens issued for it |
| Delegation | `Credential.OnBehalfOf` checked against `Identity.UserRights`; an agent acting on behalf of a user |
| Least privilege | Every omission is a denial; effective authority is the intersection of grant, scope, and user rights |
| Trust boundary | `Taint` labels on arguments, `Flow` rules per sink, and per-agent egress `Destinations` |
| Reference monitor | `Decide`, the single point every tool call passes through |
| Policy as code | `Policy` is a Go value; each rule's behavior is pinned by a test |
| Audit trail | `AuditRecord`, one per decision, naming the agent, credential, scopes, and delegating user |

## Scope and boundaries

In scope: mediation of a single tool call by verified agent identity, credential
scope, delegating-user rights, capability, argument provenance, guarded-sink
provenance, and egress destination; an audit record per decision; fail-closed
defaults on anything unclassified.

This is a research reference implementation of the control pattern. It is not a
production identity system.

Out of scope, by design:

- Credential issuance, rotation, and revocation. The package verifies a credential against a public key the caller supplies; trust is rooted in that key. A credential stays valid until its expiry.
- Proof of possession. A credential is a bearer credential. A valid credential taken from an agent's context and replayed inside its lifetime is allowed, and `TestIdentityScorecard` pins that case as a documented miss. Binding a credential to its holder (mTLS-bound SVIDs, DPoP) sits outside a pure decision function.
- Scope vocabulary. A scope is a tool name. OAuth scopes that cover several operations map to several entries.

- Content and intent analysis. The broker reasons about provenance and flow, not meaning. An injection that rides a permitted flow is not caught, and the evaluation scores that case as a documented miss.
- Cross-call and session state. Each decision is independent of the calls around it.
- Enforcement. `Decide` returns a verdict; the caller enforces it where the tool runs.
- Concurrency. `Decide` is arithmetic over a snapshot and holds no lock; serialize calls or hold a lease before relying on it under concurrent writers.

## Prior art

The design is a reference monitor applied to agent tool calls: a single decision
point that mediates every consequential action, is tamper-isolated from the code
it governs, and is small enough to reason about. The separation of untrusted data
from the control path follows the capability and information-flow approach in
CaMeL (Debenedetti et al., "Defeating Prompt Injections by Design",
arXiv:2503.18813). The implementation here is original.

## Status

A decision without identity takes about 1 microsecond. A decision with identity
takes about 60 to 70 microseconds on a two-core cloud VM, nearly all of it one
ed25519 signature verification. `BenchmarkDecide` and `BenchmarkDecideIdentity`
reproduce both figures.

Single-threaded arithmetic over a snapshot. The decision has no built-in
protection against a check-to-act race across concurrent requests; serialize
calls through the broker or add a lease before relying on it under concurrency.

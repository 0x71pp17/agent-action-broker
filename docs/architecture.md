# Architecture

## Layout

```
agent-action-broker/
├── README.md
├── LICENSE
├── Makefile
├── go.mod
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   └── architecture.md
├── SECURITY.md
├── cmd/
│   └── adeval/
│       └── main.go           evaluation scorecard CLI
├── eval/
│   └── agentdojo/
│       ├── scenario.go       Suite, Call, Scenario, adapter to broker.Request
│       ├── scenarios.go      bundled scenarios and the eval Policy
│       ├── eval.go           Evaluate, Scorecard, the two axes
│       └── eval_test.go      scorecard and documented-miss tests
└── broker/                   public API, imported as .../agent-action-broker/broker
    ├── verdict.go            types, policy, Validate, violation ids
    ├── decide.go             decision core
    ├── credential.go         Credential, Identity, credential and scope checks
    ├── audit.go              AuditRecord, AuditSink, JSONLSink, DecideAudited
    ├── decide_test.go        incident fixtures
    ├── identity_test.go      identity scorecard, FuzzIdentity, BenchmarkDecideIdentity
    ├── audit_test.go         audit-trail tests
    ├── fuzz_test.go          FuzzDecide, BenchmarkDecide
    └── example_test.go       runnable godoc example
```

## What each file owns

| Path | Owns |
|---|---|
| `broker/verdict.go` | The data model: `Sink`, `Taint`, `Request`, `Policy`, `Verdict`. No logic. |
| `broker/decide.go` | The decision. `Decide(Request, Policy) Verdict`, pure and fail-closed, no I/O. |
| `broker/credential.go` | Identity: `Credential`, its canonical signing encoding, `Identity`, the credential and scope checks, `Verdict.ForAgent`. Verification only; no signing code. |
| `broker/identity_test.go` | The same requests decided with identity off and on, pinned as a scorecard; encoding collision test; `FuzzIdentity`. |
| `broker/decide_test.go` | Concrete attacks replayed against one baseline policy, each asserting the rule that fires. |
| `broker/audit.go` | The audit trail: `AuditRecord`, `AuditSink`, `JSONLSink`, `DecideAudited`. |
| `eval/agentdojo/` | AgentDojo-modeled evaluation: scenarios, adapter, and the scorecard. |
| `cmd/adeval/main.go` | CLI that prints the scorecard in text or JSON. |

## Decision order

`Decide` evaluates a request in this order and stops at the first failure:

| Step | Violation id | Fails when |
|---|---|---|
| 1 | `credential` | no credential, no decision time, a signature that does not verify, an expired credential, a wrong audience, or a subject other than the requesting agent |
| 2 | `unknown-tool` | the tool has no declared sink |
| 3 | `capability` | the agent was not granted the tool |
| 4 | `scope` | the credential does not carry the tool as a scope |
| 5 | `delegation` | the delegating user may not reach the tool |
| 6 | `no-provenance` | a guarded sink was called with no arguments to check |
| 7 | `unknown-taint` | an argument's provenance was never established |
| 8 | `flow` | a classified taint may not reach this sink |
| 9 | `destination` | a `net.out` call targets a host off the agent's egress list |

Steps 1, 4, and 5 run when `Policy.Identity` is set. Step 1 runs before the tool
lookup, so an unauthenticated caller receives the same `credential` denial for a
registered tool and an unregistered one.

Every denial returns a `Downgrade`: the smallest change that would admit an
equivalent call. An allow returns no downgrade and no violations.

## Identity

| Element | Role |
|---|---|
| `Credential` | Scoped grant: id, subject, audience, scopes, delegating user, expiry, ed25519 signature |
| `Credential.SigningBytes` | Canonical encoding the issuer signs; every field and every scope is length-prefixed |
| `Identity.Issuer` | Public key credentials verify under |
| `Identity.Audience` | The value a credential's audience must equal |
| `Identity.UserRights` | Tools each delegating user may reach |
| `Request.Now` | Decision time, supplied by the caller; `Decide` reads no clock |

Effective authority for a call is the intersection of `Policy.Capabilities` for
the agent, `Credential.Scopes`, and, for a delegated call,
`Identity.UserRights` for the delegating user.

## Audit record

| Field | Content |
|---|---|
| `time`, `agent`, `tool`, `sink` | when, who, what, and the sink the tool reaches |
| `allowed`, `violations` | the outcome and the rule ids that failed |
| `dest` | egress destination, when present |
| `credential` | id of the credential presented |
| `on_behalf_of` | delegating user, when present |
| `scopes` | scopes the credential carried |
| `verified` | whether the agent's identity was authenticated |

## Extension points

| To add | Change |
|---|---|
| A new consequential operation | a `Sink` constant in `verdict.go`, plus its `Flow` entry in the policy |
| A new provenance class | a `Taint` constant in `verdict.go`, plus its placement in the `Flow` rules |
| A new tool | a `Tools` entry mapping the tool to a sink, and a grant under `Capabilities` |
| Verified identity | set `Policy.Identity` with the issuer key and audience; issue credentials signed over `SigningBytes` |
| A delegating user | an `Identity.UserRights` entry listing the tools the user may reach |
| The strict posture on a sink | add the sink to `GuardedSinks`; remove it for the permissive posture |

## Prior art

A reference monitor applied to agent tool calls: complete mediation of every
consequential action, isolation from the code it governs, and a core small enough
to verify. Data-and-control separation follows CaMeL (arXiv:2503.18813). The
implementation is original.

## Evaluation

`eval/agentdojo` scores the policy on injection block rate and utility retention,
modeled on AgentDojo (arXiv:2406.13352). It runs offline against `Scenario`
definitions; a live AgentDojo run is scored by exporting its traces into that
shape through the same adapter. The bundled set includes one injection that rides
a permitted flow, scored as a miss, so the scorecard reflects a real limit of
provenance-based control rather than a tuned result.

## Boundary

`Decide` reads nothing from the environment and performs no call. Enforcement of
its verdict happens at the caller, which is where the tool actually runs. The
decision is snapshot arithmetic and carries no concurrency control; serialize
calls through the broker or hold a lease before relying on it under concurrent
requests.

Credential issuance, rotation, revocation, and proof of possession sit outside
the package. A credential is a bearer credential, valid until its expiry.

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
    ├── audit.go              AuditRecord, AuditSink, JSONLSink, DecideAudited
    ├── decide_test.go        incident fixtures
    ├── audit_test.go         audit-trail tests
    ├── fuzz_test.go          FuzzDecide, BenchmarkDecide
    └── example_test.go       runnable godoc example
```

## What each file owns

| Path | Owns |
|---|---|
| `broker/verdict.go` | The data model: `Sink`, `Taint`, `Request`, `Policy`, `Verdict`. No logic. |
| `broker/decide.go` | The decision. `Decide(Request, Policy) Verdict`, pure and fail-closed, no I/O. |
| `broker/decide_test.go` | Concrete attacks replayed against one baseline policy, each asserting the rule that fires. |
| `broker/audit.go` | The audit trail: `AuditRecord`, `AuditSink`, `JSONLSink`, `DecideAudited`. |
| `eval/agentdojo/` | AgentDojo-modeled evaluation: scenarios, adapter, and the scorecard. |
| `cmd/adeval/main.go` | CLI that prints the scorecard in text or JSON. |

## Decision order

`Decide` evaluates a request in this order and stops at the first failure:

| Step | Violation id | Fails when |
|---|---|---|
| 1 | `unknown-tool` | the tool has no declared sink |
| 2 | `capability` | the agent was not granted the tool |
| 3 | `no-provenance` | a guarded sink was called with no arguments to check |
| 4 | `unknown-taint` | an argument's provenance was never established |
| 5 | `flow` | a classified taint may not reach this sink |
| 6 | `destination` | a `net.out` call targets a host off the agent's egress list |

Every denial returns a `Downgrade`: the smallest change that would admit an
equivalent call. An allow returns no downgrade and no violations.

## Extension points

| To add | Change |
|---|---|
| A new consequential operation | a `Sink` constant in `verdict.go`, plus its `Flow` entry in the policy |
| A new provenance class | a `Taint` constant in `verdict.go`, plus its placement in the `Flow` rules |
| A new tool | a `Tools` entry mapping the tool to a sink, and a grant under `Capabilities` |
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

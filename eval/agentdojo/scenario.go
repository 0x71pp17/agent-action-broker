// Package agentdojo evaluates the broker's policy against injection scenarios
// modeled on AgentDojo (Debenedetti et al., arXiv:2406.13352). It scores two
// axes, mirroring AgentDojo's utility and security: how many legitimate calls
// the policy still allows, and how many injection-driven calls it denies.
//
// The evaluation runs offline, against scenario definitions rather than a live
// LLM agent. A Scenario is a trace of tool calls, each carrying the provenance
// of its arguments; the call an injection would add is marked Injected. Real
// AgentDojo runs can be scored here by exporting their tool-call traces into the
// Scenario shape through the same adapter.
package agentdojo

import "github.com/0x71pp17/agent-action-broker/broker"

// Suite names the AgentDojo environment a scenario is drawn from.
type Suite string

const (
	SuiteWorkspace Suite = "workspace"
	SuiteBanking   Suite = "banking"
	SuiteTravel    Suite = "travel"
	SuiteSlack     Suite = "slack"
)

// Call is one step in a scenario's trace. ArgTaints is the provenance of the
// data feeding the call, and Dest is the egress target for a call that leaves
// the machine. Injected marks the step that exists only because of the
// injection: the call a defense must deny.
type Call struct {
	Tool      string
	ArgTaints []broker.Taint
	Dest      string
	Injected  bool
}

// Scenario is a user task and its trace. An injection scenario contains exactly
// one Injected call; a benign scenario contains none.
type Scenario struct {
	ID    string
	Suite Suite
	Task  string // the legitimate task, for context
	Goal  string // for injection scenarios, what the injection attempts
	Trace []Call
}

// injection reports whether the scenario carries an injected call and its index.
func (s Scenario) injection() (int, bool) {
	for i, c := range s.Trace {
		if c.Injected {
			return i, true
		}
	}
	return -1, false
}

// toRequest adapts a Call to a broker.Request for a fixed agent principal.
func toRequest(agent string, c Call) broker.Request {
	return broker.Request{Agent: agent, Tool: c.Tool, ArgTaints: c.ArgTaints, Dest: c.Dest}
}

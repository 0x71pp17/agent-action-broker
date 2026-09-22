// Package broker is a policy decision point for tool-using agents.
//
// It answers one question about a single tool call: may this agent make this
// call, given what the call reaches, where its arguments came from, and where
// its output goes. The answer is a Verdict carrying a machine-readable list of
// the rules that failed and, on a denial, the least-privilege change that would
// let an equivalent call through. Nothing here performs the call or reads the
// world; Decide is arithmetic over the request and the policy, so any real
// incident can be pinned as a test rather than reproduced against live tools.
package broker

import "strings"

// Sink is a class of consequential operation a tool performs. A tool with no
// consequential effect is SinkBenign; a tool the policy has never classified is
// SinkUnknown and is refused.
type Sink string

const (
	SinkBenign     Sink = "benign"
	SinkShell      Sink = "shell.exec"
	SinkNetOut     Sink = "net.out"
	SinkFileWrite  Sink = "file.write"
	SinkSecretRead Sink = "secret.read"
	SinkUnknown    Sink = "unknown"
)

// Taint is the provenance of a value flowing into a call. Provenance that has
// not been established is TaintUnknown and is refused into every sink.
type Taint string

const (
	TaintTrusted       Taint = "trusted"        // operator or system origin
	TaintUntrustedWeb  Taint = "untrusted.web"  // fetched content, open-web tool output
	TaintTenantPrivate Taint = "tenant.private" // another principal's private data
	TaintUnknown       Taint = "unknown"        // provenance not established
)

// Request is one tool call presented for a decision.
type Request struct {
	Agent     string  // the agent principal making the call
	Tool      string  // the tool name being invoked
	ArgTaints []Taint // provenance of each argument feeding the call
	Dest      string  // egress destination for net.out sinks; empty otherwise
}

// Policy is the standing configuration a decision is made against. Every map
// omission is a denial: an ungranted tool, an unclassified tool, a taint not
// listed for a sink, and a destination not on an agent's egress list are all
// refused.
type Policy struct {
	Capabilities map[string][]string // tools each agent is granted
	Tools        map[string]Sink     // the sink each known tool reaches
	Flow         map[Sink][]Taint    // taints permitted to reach each sink
	Destinations map[string][]string // egress destinations each agent may reach
	// GuardedSinks lists sinks whose calls must carry established provenance.
	// A call to a guarded sink with no arguments is refused, because a
	// consequential action with no inputs cannot be shown to run on trusted
	// context. Leaving this empty makes the grant itself the authorization.
	GuardedSinks []Sink
}

// Validate reports policy configuration problems that would otherwise surface
// only at decision time: a tool granted to an agent but never classified with a
// sink. It returns nil when the policy is internally consistent.
func (p Policy) Validate() []string {
	var problems []string
	for agent, tools := range p.Capabilities {
		for _, tool := range tools {
			if _, ok := p.Tools[tool]; !ok {
				problems = append(problems, "agent "+agent+" is granted "+tool+", which has no declared sink")
			}
		}
	}
	return problems
}

// Verdict is the decision. Downgrade is populated on a denial with the smallest
// change that would admit an equivalent call, and is empty on an allow.
type Verdict struct {
	Allowed    bool     `json:"allowed"`
	Reason     string   `json:"reason"`
	Downgrade  string   `json:"downgrade,omitempty"`
	Violations []string `json:"violations,omitempty"` // rule ids; see the Violation constants
}

// Violation ids. Callers switch on these rather than string literals.
const (
	ViolationUnknownTool  = "unknown-tool"
	ViolationCapability   = "capability"
	ViolationNoProvenance = "no-provenance"
	ViolationUnknownTaint = "unknown-taint"
	ViolationFlow         = "flow"
	ViolationDestination  = "destination"
)

// String renders a verdict for a log line.
func (v Verdict) String() string {
	if v.Allowed {
		return "allow: " + v.Reason
	}
	return "deny [" + strings.Join(v.Violations, ",") + "]: " + v.Reason
}

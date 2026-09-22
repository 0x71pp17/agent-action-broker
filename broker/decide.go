package broker

import "fmt"

// Decide returns the Verdict for one request under one policy.
//
// The checks run in a fixed order, least-privilege first and fail-closed on
// anything unclassified:
//
//  1. unknown-tool   the tool has no declared sink
//  2. capability     the agent was not granted the tool
//  3. no-provenance  a guarded sink was called with no arguments to check
//  4. unknown-taint  an argument's provenance was never established
//  5. flow           a classified taint may not reach this sink
//  6. destination    a net.out call targets a host off the agent's egress list
//
// The first failing check decides the call; a denial always carries a Downgrade.
func Decide(req Request, p Policy) Verdict {
	sink, known := p.Tools[req.Tool]
	if !known || sink == SinkUnknown {
		return Verdict{
			Reason:     fmt.Sprintf("tool %q has no declared sink: an unclassified capability cannot be brokered", req.Tool),
			Downgrade:  fmt.Sprintf("register %q in the tool registry with an explicit sink, then re-request", req.Tool),
			Violations: []string{ViolationUnknownTool},
		}
	}

	if !contains(p.Capabilities[req.Agent], req.Tool) {
		return Verdict{
			Reason:     fmt.Sprintf("agent %q is not granted %q", req.Agent, req.Tool),
			Downgrade:  fmt.Sprintf("grant %q to agent %q as a scoped capability, or route the call to an agent that already holds it", req.Tool, req.Agent),
			Violations: []string{ViolationCapability},
		}
	}

	if isGuarded(p.GuardedSinks, sink) && len(req.ArgTaints) == 0 {
		return Verdict{
			Reason:     fmt.Sprintf("%q reaches %s with no arguments, so its provenance cannot be established", req.Tool, sink),
			Downgrade:  fmt.Sprintf("pass the operation's inputs as arguments so their provenance can be checked against %s, or route the call through human approval", sink),
			Violations: []string{ViolationNoProvenance},
		}
	}

	allowed := p.Flow[sink]
	for _, t := range req.ArgTaints {
		if t == TaintUnknown {
			return Verdict{
				Reason:     fmt.Sprintf("an argument to %q has unestablished provenance and cannot reach %s", req.Tool, sink),
				Downgrade:  fmt.Sprintf("establish provenance for every argument before reaching %s; unknown taint is refused into all sinks", sink),
				Violations: []string{ViolationUnknownTaint},
			}
		}
		if !contains(taintStrings(allowed), string(t)) {
			return Verdict{
				Reason:     fmt.Sprintf("%s data may not reach %s (call %q)", t, sink, req.Tool),
				Downgrade:  fmt.Sprintf("route this call through human approval, or strip the %s argument before it reaches %s", t, sink),
				Violations: []string{ViolationFlow},
			}
		}
	}

	if sink == SinkNetOut && req.Dest != "" && !contains(p.Destinations[req.Agent], req.Dest) {
		return Verdict{
			Reason:     fmt.Sprintf("agent %q may not send to %q", req.Agent, req.Dest),
			Downgrade:  fmt.Sprintf("add %q to the egress allowlist for %q, or send to an approved destination", req.Dest, req.Agent),
			Violations: []string{ViolationDestination},
		}
	}

	return Verdict{
		Allowed: true,
		Reason:  fmt.Sprintf("agent %q may call %q (sink %s): granted, provenance clears the flow rules%s", req.Agent, req.Tool, sink, destNote(sink, req.Dest)),
	}
}

func destNote(sink Sink, dest string) string {
	if sink == SinkNetOut && dest != "" {
		return fmt.Sprintf(", destination %q on the egress list", dest)
	}
	return ""
}

func isGuarded(sinks []Sink, s Sink) bool {
	for _, x := range sinks {
		if x == s {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

func taintStrings(tt []Taint) []string {
	out := make([]string, len(tt))
	for i, t := range tt {
		out[i] = string(t)
	}
	return out
}

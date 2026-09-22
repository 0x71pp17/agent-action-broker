package broker

import "testing"

// baseline is the fixture every incident is replayed against: one researcher
// agent with a narrow grant, a small tool registry, and flow rules that let
// only operator-origin data reach the consequential sinks.
func baseline() Policy {
	return Policy{
		Capabilities: map[string][]string{
			"researcher": {"web.fetch", "doc.summarize", "report.write"},
		},
		Tools: map[string]Sink{
			"web.fetch":     SinkNetOut,
			"doc.summarize": SinkBenign,
			"report.write":  SinkFileWrite,
			"shell.run":     SinkShell,
			"vault.read":    SinkSecretRead,
		},
		Flow: map[Sink][]Taint{
			SinkBenign:     {TaintTrusted, TaintUntrustedWeb, TaintTenantPrivate},
			SinkNetOut:     {TaintTrusted},
			SinkFileWrite:  {TaintTrusted, TaintTenantPrivate},
			SinkShell:      {TaintTrusted},
			SinkSecretRead: {TaintTrusted},
		},
		Destinations: map[string][]string{
			"researcher": {"api.internal.example"},
		},
		// Strict posture: consequential sinks must carry arguments whose
		// provenance can be checked. Empty this list for the permissive posture,
		// where holding the grant is the authorization.
		GuardedSinks: []Sink{SinkShell, SinkNetOut, SinkFileWrite, SinkSecretRead},
	}
}

// Indirect prompt injection: content fetched from the open web tries to drive a
// second outbound call carrying that same attacker-influenced data. The call is
// granted, but untrusted.web reaching net.out is refused by the flow rules.
func TestIndirectInjection_UntrustedWebReachesNetOut(t *testing.T) {
	v := Decide(Request{
		Agent:     "researcher",
		Tool:      "web.fetch",
		ArgTaints: []Taint{TaintUntrustedWeb},
		Dest:      "api.internal.example",
	}, baseline())

	assertDenied(t, v, "flow")
	if v.Downgrade == "" {
		t.Error("a flow denial must propose a downgrade")
	}
}

// Exfiltration: trusted-looking data addressed to a host that is not on the
// agent's egress list. Provenance clears, the destination does not.
func TestExfiltration_DestinationOffAllowlist(t *testing.T) {
	v := Decide(Request{
		Agent:     "researcher",
		Tool:      "web.fetch",
		ArgTaints: []Taint{TaintTrusted},
		Dest:      "collector.attacker.example",
	}, baseline())

	assertDenied(t, v, "destination")
}

// Capability creep: the agent reaches for a shell it was never granted. This is
// refused before any flow reasoning, so an ungranted dangerous tool never even
// gets its arguments inspected.
func TestCapabilityCreep_UngrantedShell(t *testing.T) {
	v := Decide(Request{
		Agent:     "researcher",
		Tool:      "shell.run",
		ArgTaints: []Taint{TaintTrusted},
	}, baseline())

	assertDenied(t, v, "capability")
}

// Fail-closed on provenance: a benign sink still refuses an argument whose
// origin was never established. Not knowing where data came from is a denial,
// not a default-allow.
func TestUnknownProvenance_FailsClosedEvenAtBenignSink(t *testing.T) {
	v := Decide(Request{
		Agent:     "researcher",
		Tool:      "doc.summarize",
		ArgTaints: []Taint{TaintUnknown},
	}, baseline())

	assertDenied(t, v, "unknown-taint")
}

// Fail-closed on classification: a tool with no declared sink cannot be
// brokered at all, whoever asks.
func TestUnknownTool_FailsClosed(t *testing.T) {
	v := Decide(Request{
		Agent: "researcher",
		Tool:  "payments.transfer",
	}, baseline())

	assertDenied(t, v, "unknown-tool")
}

// The call that should pass: an in-scope tool, a benign sink, and a taint the
// flow rules permit there.
func TestLegitimateInScopeCall_Allowed(t *testing.T) {
	v := Decide(Request{
		Agent:     "researcher",
		Tool:      "doc.summarize",
		ArgTaints: []Taint{TaintUntrustedWeb},
	}, baseline())

	if !v.Allowed {
		t.Fatalf("legitimate call refused: %s", v.Reason)
	}
	if v.Downgrade != "" {
		t.Errorf("an allow must not carry a downgrade, got %q", v.Downgrade)
	}
	if len(v.Violations) != 0 {
		t.Errorf("an allow must carry no violations, got %v", v.Violations)
	}
}

// Every denial the fixtures produce must hand back an actionable next step: a
// verdict that says no without saying what to do instead is not usable.
func TestEveryDenialCarriesADowngrade(t *testing.T) {
	denials := []Request{
		{Agent: "researcher", Tool: "web.fetch", ArgTaints: []Taint{TaintUntrustedWeb}, Dest: "api.internal.example"},
		{Agent: "researcher", Tool: "web.fetch", ArgTaints: []Taint{TaintTrusted}, Dest: "collector.attacker.example"},
		{Agent: "researcher", Tool: "shell.run", ArgTaints: []Taint{TaintTrusted}},
		{Agent: "researcher", Tool: "doc.summarize", ArgTaints: []Taint{TaintUnknown}},
		{Agent: "researcher", Tool: "payments.transfer"},
	}
	for _, r := range denials {
		v := Decide(r, baseline())
		if v.Allowed {
			t.Errorf("expected denial for %+v", r)
			continue
		}
		if v.Downgrade == "" {
			t.Errorf("denial for %s/%s carried no downgrade", r.Agent, r.Tool)
		}
	}
}

func assertDenied(t *testing.T, v Verdict, wantViolation string) {
	t.Helper()
	if v.Allowed {
		t.Fatalf("expected denial, got allow: %s", v.Reason)
	}
	if len(v.Violations) == 0 || v.Violations[0] != wantViolation {
		t.Fatalf("expected violation %q, got %v (%s)", wantViolation, v.Violations, v.Reason)
	}
}

// A granted but consequential tool called with no arguments is refused under the
// strict posture: there is nothing whose provenance can be shown to be trusted.
func TestGuardedSink_NoArgumentsFailsClosed(t *testing.T) {
	p := baseline()
	p.Capabilities["researcher"] = append(p.Capabilities["researcher"], "shell.run")

	v := Decide(Request{Agent: "researcher", Tool: "shell.run"}, p)
	assertDenied(t, v, "no-provenance")
	if v.Downgrade == "" {
		t.Error("a no-provenance denial must propose a downgrade")
	}
}

// The same call is admitted under the permissive posture, where the grant is the
// authorization. Emptying GuardedSinks is the only change.
func TestGuardedSink_PermissivePostureAdmitsNoArgCall(t *testing.T) {
	p := baseline()
	p.Capabilities["researcher"] = append(p.Capabilities["researcher"], "shell.run")
	p.GuardedSinks = nil

	v := Decide(Request{Agent: "researcher", Tool: "shell.run"}, p)
	if !v.Allowed {
		t.Fatalf("permissive posture refused a granted no-arg call: %s", v.Reason)
	}
}

// A clean policy validates without complaint; a grant to an unclassified tool is
// surfaced at load time instead of only at decision time.
func TestPolicyValidate(t *testing.T) {
	if problems := baseline().Validate(); len(problems) != 0 {
		t.Errorf("baseline policy should validate clean, got %v", problems)
	}

	p := baseline()
	p.Capabilities["researcher"] = append(p.Capabilities["researcher"], "ghost.tool")
	problems := p.Validate()
	if len(problems) != 1 {
		t.Fatalf("expected one problem for a dangling grant, got %v", problems)
	}
}

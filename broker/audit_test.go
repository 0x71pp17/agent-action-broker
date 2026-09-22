package broker

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDecideAudited_WritesOneRecordPerDecision(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONLSink(&buf)

	// shell.run is not granted to researcher, so this is a capability denial.
	v, err := DecideAudited(Request{Agent: "researcher", Tool: "shell.run", ArgTaints: []Taint{TaintTrusted}}, baseline(), sink)
	if err != nil {
		t.Fatalf("record failed: %v", err)
	}
	if v.Allowed {
		t.Fatal("expected a denial")
	}

	var rec AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("audit line is not valid json: %v", err)
	}
	if rec.Agent != "researcher" || rec.Tool != "shell.run" || rec.Allowed {
		t.Errorf("record does not reflect the decision: %+v", rec)
	}
	if len(rec.Violations) == 0 || rec.Violations[0] != ViolationCapability {
		t.Errorf("record missing the violation, got %v", rec.Violations)
	}
	if rec.Time.IsZero() {
		t.Error("record has no timestamp")
	}
}

func TestDecideAudited_NilSinkStillDecides(t *testing.T) {
	v, err := DecideAudited(Request{Agent: "researcher", Tool: "doc.summarize", ArgTaints: []Taint{TaintTrusted}}, baseline(), nil)
	if err != nil {
		t.Fatalf("nil sink should not error: %v", err)
	}
	if !v.Allowed {
		t.Errorf("expected allow, got %s", v.Reason)
	}
}

package broker

import "testing"

// FuzzDecide asserts two invariants over arbitrary input: Decide never panics,
// and an allow is always clean (no violations, no downgrade). A denial that
// leaked through as an allow, or a crash on malformed input, fails here.
func FuzzDecide(f *testing.F) {
	f.Add("researcher", "web.fetch", "untrusted.web", "api.internal.example")
	f.Add("researcher", "shell.run", "unknown", "")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, agent, tool, taint, dest string) {
		v := Decide(Request{
			Agent:     agent,
			Tool:      tool,
			ArgTaints: []Taint{Taint(taint)},
			Dest:      dest,
		}, baseline())

		if v.Allowed && (len(v.Violations) != 0 || v.Downgrade != "") {
			t.Fatalf("an allow carried violations or a downgrade: %+v", v)
		}
		if !v.Allowed && len(v.Violations) == 0 {
			t.Fatalf("a denial carried no violation id: %+v", v)
		}
	})
}

func BenchmarkDecide(b *testing.B) {
	p := baseline()
	req := Request{Agent: "researcher", Tool: "web.fetch", ArgTaints: []Taint{TaintUntrustedWeb}, Dest: "api.internal.example"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Decide(req, p)
	}
}

// Command adeval scores the broker's policy against the bundled AgentDojo-modeled
// scenarios and prints a scorecard. It evaluates the policy layer offline; it
// does not run a live LLM agent.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/0x71pp17/agent-action-broker/eval/agentdojo"
)

func main() {
	format := flag.String("format", "text", "output format: text or json")
	flag.Parse()

	sc := agentdojo.Evaluate(agentdojo.Scenarios(), agentdojo.Policy())

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sc); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(2)
		}
		return
	}

	fmt.Printf("%-34s %-10s %-10s %s\n", "scenario", "suite", "result", "detail")
	for _, o := range sc.Outcomes {
		result := "blocked"
		if o.Kind == "benign" {
			result = "allowed"
		}
		if !o.Pass {
			if o.Kind == "injection" {
				result = "MISSED"
			} else {
				result = "OVER-BLOCKED"
			}
		}
		fmt.Printf("%-34s %-10s %-10s %s\n", o.Scenario, o.Suite, result, o.Detail)
	}
	fmt.Printf("\nby suite:\n")
	for _, st := range sc.Suites {
		fmt.Printf("  %-10s injections %d/%d blocked, utility %d/%d kept\n",
			st.Suite, st.InjectionsBlocked, st.InjectionsTotal, st.BenignKept, st.BenignTotal)
	}
	fmt.Printf("\ninjection block rate: %d/%d (%.0f%%)\n", sc.InjectionsBlocked, sc.InjectionsTotal, sc.BlockRate()*100)
	fmt.Printf("utility retention:    %d/%d (%.0f%%)\n", sc.BenignKept, sc.BenignTotal, sc.UtilityRate()*100)
}

package broker_test

import (
	"fmt"

	"github.com/0x71pp17/agent-action-broker/broker"
)

// ExampleDecide shows a denial: content fetched from the open web tries to drive
// an outbound call, which the flow rules refuse.
func ExampleDecide() {
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

	fmt.Println("allowed:", v.Allowed)
	fmt.Println("violation:", v.Violations[0])
	// Output:
	// allowed: false
	// violation: flow
}

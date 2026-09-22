package broker

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditRecord is the durable evidence of one decision. It records what was asked
// and what was decided, so a governed action leaves a trail independent of the
// tool that ran.
type AuditRecord struct {
	Time       time.Time `json:"time"`
	Agent      string    `json:"agent"`
	Tool       string    `json:"tool"`
	Sink       Sink      `json:"sink"`
	Allowed    bool      `json:"allowed"`
	Violations []string  `json:"violations,omitempty"`
}

// AuditSink receives one record per decision. An implementation used with a
// broker called from multiple goroutines must be safe for concurrent use.
type AuditSink interface {
	Record(AuditRecord) error
}

// DecideAudited evaluates the request and writes an audit record before
// returning. The sink error is returned alongside the verdict rather than
// folded into it: the decision stands whether or not it was recorded, and the
// caller chooses whether an unrecorded decision is acceptable. A nil sink skips
// recording.
func DecideAudited(req Request, p Policy, sink AuditSink) (Verdict, error) {
	v := Decide(req, p)
	if sink == nil {
		return v, nil
	}
	return v, sink.Record(AuditRecord{
		Time:       time.Now().UTC(),
		Agent:      req.Agent,
		Tool:       req.Tool,
		Sink:       p.Tools[req.Tool],
		Allowed:    v.Allowed,
		Violations: v.Violations,
	})
}

// JSONLSink writes one JSON object per line to an io.Writer, an append-only
// format a log pipeline can tail. It is safe for concurrent use.
type JSONLSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONLSink returns a sink that appends records to w.
func NewJSONLSink(w io.Writer) *JSONLSink { return &JSONLSink{w: w} }

// Record marshals r and writes it followed by a newline.
func (s *JSONLSink) Record(r AuditRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}

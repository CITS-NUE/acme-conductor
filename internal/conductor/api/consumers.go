package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CITS-NUE/acme-conductor/internal/conductor/registry"
)

// Bounds of a target's consumer ledger (issue #74). Lengths are in bytes
// of UTF-8.
const (
	MaxConsumers             = 20
	MaxConsumerServiceLength = 256
	MaxConsumerContactLength = 256
	MaxConsumerNoteLength    = 512
)

// Consumer is one entry of a target's consumer ledger: free text for
// people, never interpreted by the Conductor or a Runner and never part of
// a JobSpec.
type Consumer struct {
	Service string `json:"service"`
	Contact string `json:"contact"`
	Note    string `json:"note"`
}

// ConsumersResource is a target's consumer ledger. Version is its own
// optimistic-locking counter (0 before the first write); editing the
// ledger never changes the target's revision.
type ConsumersResource struct {
	TargetID           string     `json:"targetId"`
	Version            int64      `json:"version"`
	Items              []Consumer `json:"items"`
	UpdatedAt          *time.Time `json:"updatedAt,omitempty"`
	UpdatedBy          string     `json:"updatedBy,omitempty"`
	UpdatedByAuthority string     `json:"updatedByAuthority,omitempty"`
}

// ConsumersInput replaces a ledger: Version must be the current one.
type ConsumersInput struct {
	Version int64      `json:"version"`
	Items   []Consumer `json:"items"`
}

func consumersResource(c *registry.Consumers) ConsumersResource {
	res := ConsumersResource{TargetID: c.TargetID, Version: c.Version, Items: []Consumer{}, UpdatedAt: c.UpdatedAt, UpdatedBy: c.UpdatedBy, UpdatedByAuthority: c.UpdatedByAuthority}
	for _, e := range c.Items {
		res.Items = append(res.Items, Consumer{Service: e.Service, Contact: e.Contact, Note: e.Note})
	}
	return res
}

// ledgerText checks one free-text field of the ledger the way an owner is
// checked: trimmed, bounded, valid UTF-8, printable (one line).
func ledgerText(field, v string, max int, required bool) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		if required {
			return "", badRequest("%s is required", field)
		}
		return "", nil
	}
	if len(v) > max || !utf8.ValidString(v) {
		return "", badRequest("%s must be valid UTF-8 of at most %d bytes", field, max)
	}
	for _, r := range v {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return "", badRequest("%s must contain only printable characters on one line", field)
		}
	}
	return v, nil
}

func validateConsumers(in []Consumer) ([]registry.Consumer, error) {
	if len(in) > MaxConsumers {
		return nil, badRequest("items: at most %d consumers per target", MaxConsumers)
	}
	out := make([]registry.Consumer, 0, len(in))
	for i, e := range in {
		svc, err := ledgerText(fmt.Sprintf("items[%d].service", i), e.Service, MaxConsumerServiceLength, true)
		if err != nil {
			return nil, err
		}
		contact, err := ledgerText(fmt.Sprintf("items[%d].contact", i), e.Contact, MaxConsumerContactLength, true)
		if err != nil {
			return nil, err
		}
		note, err := ledgerText(fmt.Sprintf("items[%d].note", i), e.Note, MaxConsumerNoteLength, false)
		if err != nil {
			return nil, err
		}
		out = append(out, registry.Consumer{Service: svc, Contact: contact, Note: note})
	}
	return out, nil
}

func (s *Server) handleGetTargetConsumers(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.reg.GetTargetConsumers(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, consumersResource(c))
}

// handlePutTargetConsumers replaces a target's consumer ledger (admin). The
// audit event records counts only: the entries name people and contacts,
// which are not copied into the append-only log.
func (s *Server) handlePutTargetConsumers(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in ConsumersInput
	if err := decodeBody(r, &in, false); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Version < 0 {
		s.fail(w, r, badRequest("version must not be negative"))
		return
	}
	items, err := validateConsumers(in.Items)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	prev, err := s.reg.GetTargetConsumers(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	caller := PrincipalFrom(r.Context())
	c := &registry.Consumers{TargetID: id, Items: items, UpdatedBy: caller.Name, UpdatedByAuthority: caller.Authority}
	ev := &registry.AuditEvent{Actor: caller.Name, ActorAuthority: caller.Authority, Action: registry.AuditTargetConsumersUpdated,
		Detail: fmt.Sprintf("consumers updated: %d -> %d entries (version %d)", len(prev.Items), len(items), in.Version+1)}
	if err := s.reg.SetTargetConsumers(r.Context(), c, in.Version, ev); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, consumersResource(c))
}

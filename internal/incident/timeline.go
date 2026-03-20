package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/audit"
)

type TimelineEntry struct {
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"`
	Action       string    `json:"action"`
	Status       string    `json:"status"`
	Actor        string    `json:"actor,omitempty"`
	Target       string    `json:"target,omitempty"`
	TargetHost   string    `json:"target_host,omitempty"`
	Message      string    `json:"message,omitempty"`
	LikelyChange bool      `json:"likely_change,omitempty"`
}

type Timeline struct {
	Incident          Record          `json:"incident"`
	WindowMinutes     int             `json:"window_minutes"`
	Entries           []TimelineEntry `json:"entries"`
	CorrelatedChanges []TimelineEntry `json:"correlated_changes,omitempty"`
}

type TimelineBuilder struct {
	Store audit.Store
	Now   func() time.Time
}

func (b TimelineBuilder) Build(record Record, window time.Duration) (Timeline, error) {
	if b.Store == nil {
		return Timeline{}, fmt.Errorf("audit store not configured")
	}
	if window <= 0 {
		window = 90 * time.Minute
	}
	start := record.FirstSeenAt.Add(-window)
	if start.IsZero() {
		start = time.Now().UTC().Add(-window)
		if b.Now != nil {
			start = b.Now().UTC().Add(-window)
		}
	}
	end := record.LastSeenAt
	if end.IsZero() {
		end = record.UpdatedAt
	}
	if end.IsZero() {
		end = time.Now().UTC()
		if b.Now != nil {
			end = b.Now().UTC()
		}
	}

	events, err := b.Store.List(audit.Query{
		Since:    start,
		Projects: []string{record.Project},
		Env:      record.Env,
		Limit:    1000,
	})
	if err != nil {
		return Timeline{}, err
	}

	timeline := Timeline{
		Incident:      record,
		WindowMinutes: int(window / time.Minute),
		Entries:       make([]TimelineEntry, 0, len(events)+2),
	}
	for _, evt := range events {
		if evt.Time.After(end.Add(window)) {
			continue
		}
		entry := timelineEntry(evt, record)
		if entry.Kind == "" {
			continue
		}
		timeline.Entries = append(timeline.Entries, entry)
		if entry.LikelyChange {
			timeline.CorrelatedChanges = append(timeline.CorrelatedChanges, entry)
		}
	}
	sort.SliceStable(timeline.Entries, func(i, j int) bool {
		return timeline.Entries[i].Time.Before(timeline.Entries[j].Time)
	})
	sort.SliceStable(timeline.CorrelatedChanges, func(i, j int) bool {
		return timeline.CorrelatedChanges[i].Time.After(timeline.CorrelatedChanges[j].Time)
	})
	if len(timeline.CorrelatedChanges) > 5 {
		timeline.CorrelatedChanges = timeline.CorrelatedChanges[:5]
	}
	return timeline, nil
}

func timelineEntry(evt audit.Event, record Record) TimelineEntry {
	kind := classifyEvent(evt)
	if kind == "" {
		return TimelineEntry{}
	}
	entry := TimelineEntry{
		Time:       evt.Time,
		Kind:       kind,
		Action:     strings.TrimSpace(evt.Action),
		Status:     strings.TrimSpace(evt.Status),
		Actor:      strings.TrimSpace(evt.Actor),
		Target:     strings.TrimSpace(evt.Target),
		TargetHost: strings.TrimSpace(evt.TargetHost),
		Message:    strings.TrimSpace(evt.Message),
	}
	entry.LikelyChange = kind == "change" && likelyCorrelated(evt.Time, record.FirstSeenAt)
	return entry
}

func classifyEvent(evt audit.Event) string {
	actionName := strings.TrimSpace(evt.Action)
	switch actionName {
	case "health_cycle", "health_run", "slo_eval", "alertmanager_receive":
		return "signal"
	case "incident_ack", "incident_assign", "incident_sync", "alertmanager_silence", "alertmanager_unsilence", "alertmanager_reconcile":
		return "incident"
	case "notify":
		return ""
	case "discovery_apply", "discover_host":
		return "change"
	}
	if actions.IsMutating(actionName) {
		return "change"
	}
	if _, ok := actions.Lookup(actionName); ok {
		return "runbook"
	}
	if strings.HasPrefix(actionName, "llm_") {
		return "chatops"
	}
	return "system"
}

func likelyCorrelated(at, firstSeen time.Time) bool {
	if at.IsZero() || firstSeen.IsZero() {
		return false
	}
	if at.After(firstSeen.Add(15 * time.Minute)) {
		return false
	}
	return !at.Before(firstSeen.Add(-30 * time.Minute))
}

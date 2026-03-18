package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
)

type Controller struct {
	Notifier       Notifier
	Store          Store
	MinSeverity    string
	RepeatInterval time.Duration
	NotifyRecovery bool
	Now            func() time.Time
}

type Decision struct {
	Send   bool
	Reason string
}

func (c Controller) Process(ctx context.Context, report incident.Report) (Decision, error) {
	if c.Notifier == nil || c.Store == nil {
		return Decision{Send: false, Reason: "notifier disabled"}, nil
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	key := report.Source + "|" + report.Env
	prev, ok, err := c.Store.Get(key)
	if err != nil {
		return Decision{}, err
	}

	send, reason := c.shouldSend(report, prev, ok, now)
	next := State{
		Key:             key,
		LastStatus:      report.Status,
		LastFingerprint: report.Fingerprint,
		LastNotifiedAt:  prev.LastNotifiedAt,
		LastChangedAt:   prev.LastChangedAt,
	}
	if !ok {
		next.LastChangedAt = now
	}
	if !ok || prev.LastStatus != report.Status || prev.LastFingerprint != report.Fingerprint {
		next.LastChangedAt = now
	}
	if send {
		if err := c.Notifier.Notify(ctx, report); err != nil {
			return Decision{}, err
		}
		next.LastNotifiedAt = now
	}
	if err := c.Store.Put(next); err != nil {
		return Decision{}, err
	}
	return Decision{Send: send, Reason: reason}, nil
}

func (c Controller) shouldSend(report incident.Report, prev State, ok bool, now time.Time) (bool, string) {
	currentRank := severityRank(report.Status)
	minRank := severityRankOrDefault(c.MinSeverity, "warn")
	if currentRank < minRank {
		if ok && severityRank(prev.LastStatus) >= minRank && c.NotifyRecovery {
			return true, "recovery"
		}
		return false, "below threshold"
	}
	if !ok || severityRank(prev.LastStatus) < minRank {
		return true, "new incident"
	}
	if currentRank > severityRank(prev.LastStatus) {
		return true, "severity escalated"
	}
	if strings.TrimSpace(prev.LastFingerprint) != strings.TrimSpace(report.Fingerprint) {
		return true, "incident changed"
	}
	if c.RepeatInterval > 0 && now.Sub(prev.LastNotifiedAt) >= c.RepeatInterval {
		return true, "repeat interval reached"
	}
	return false, "duplicate suppressed"
}

func NewController(notifier Notifier, store Store, minSeverity string, repeat time.Duration, notifyRecovery bool) Controller {
	return Controller{
		Notifier:       notifier,
		Store:          store,
		MinSeverity:    strings.ToLower(strings.TrimSpace(minSeverity)),
		RepeatInterval: repeat,
		NotifyRecovery: notifyRecovery,
	}
}

func NewSQLiteStore(path string) Store {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return SQLiteStore{Path: path}
}

func DescribeDecision(d Decision) string {
	if d.Send {
		return "sent: " + d.Reason
	}
	return "suppressed: " + d.Reason
}

func ValidateMinSeverity(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "ok", "warn", "fail":
		return nil
	default:
		return fmt.Errorf("invalid notify severity: %s", v)
	}
}

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
	TriggerAfter   int
	RecoveryAfter  int
	Now            func() time.Time
}

type ControllerOptions struct {
	MinSeverity    string
	RepeatInterval time.Duration
	NotifyRecovery bool
	TriggerAfter   int
	RecoveryAfter  int
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

	next, decision := c.decide(report, prev, ok, now)
	next.Key = key
	if decision.Send {
		if err := c.Notifier.Notify(ctx, report); err != nil {
			return Decision{}, err
		}
		next.LastNotifiedAt = now
	}
	if err := c.Store.Put(next); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

func (c Controller) decide(report incident.Report, prev State, ok bool, now time.Time) (State, Decision) {
	currentRank := severityRank(report.Status)
	minRank := severityRankOrDefault(c.MinSeverity, "warn")
	triggerAfter := thresholdOrDefault(c.TriggerAfter)
	recoveryAfter := thresholdOrDefault(c.RecoveryAfter)

	next := State{
		Key:             prev.Key,
		LastStatus:      report.Status,
		LastFingerprint: report.Fingerprint,
		LastNotifiedAt:  prev.LastNotifiedAt,
		LastChangedAt:   prev.LastChangedAt,
		Open:            prev.Open,
		OpenStatus:      prev.OpenStatus,
		OpenFingerprint: prev.OpenFingerprint,
		FailureStreak:   prev.FailureStreak,
		RecoveryStreak:  prev.RecoveryStreak,
	}
	if !ok || prev.LastStatus != report.Status || prev.LastFingerprint != report.Fingerprint {
		next.LastChangedAt = now
	}

	if currentRank >= minRank {
		next.FailureStreak = prev.FailureStreak + 1
		next.RecoveryStreak = 0

		if !prev.Open {
			if next.FailureStreak < triggerAfter {
				next.Open = false
				next.OpenStatus = ""
				next.OpenFingerprint = ""
				return next, Decision{Send: false, Reason: fmt.Sprintf("awaiting trigger threshold (%d/%d)", next.FailureStreak, triggerAfter)}
			}
			next.Open = true
			next.OpenStatus = report.Status
			next.OpenFingerprint = report.Fingerprint
			if triggerAfter > 1 {
				return next, Decision{Send: true, Reason: "trigger threshold reached"}
			}
			return next, Decision{Send: true, Reason: "new incident"}
		}
		next.Open = true
		next.OpenStatus = report.Status
		next.OpenFingerprint = report.Fingerprint
		if currentRank > severityRank(prev.OpenStatus) {
			return next, Decision{Send: true, Reason: "severity escalated"}
		}
		if strings.TrimSpace(prev.OpenFingerprint) != strings.TrimSpace(report.Fingerprint) {
			return next, Decision{Send: true, Reason: "incident changed"}
		}
		if c.RepeatInterval > 0 && !prev.LastNotifiedAt.IsZero() && now.Sub(prev.LastNotifiedAt) >= c.RepeatInterval {
			return next, Decision{Send: true, Reason: "repeat interval reached"}
		}
		return next, Decision{Send: false, Reason: "duplicate suppressed"}
	}

	next.FailureStreak = 0
	if !prev.Open {
		next.Open = false
		next.OpenStatus = ""
		next.OpenFingerprint = ""
		next.RecoveryStreak = 0
		return next, Decision{Send: false, Reason: "below threshold"}
	}

	next.Open = true
	next.OpenStatus = prev.OpenStatus
	next.OpenFingerprint = prev.OpenFingerprint
	next.RecoveryStreak = prev.RecoveryStreak + 1
	if next.RecoveryStreak < recoveryAfter {
		return next, Decision{Send: false, Reason: fmt.Sprintf("awaiting recovery confirmation (%d/%d)", next.RecoveryStreak, recoveryAfter)}
	}
	next.Open = false
	next.OpenStatus = ""
	next.OpenFingerprint = ""
	next.RecoveryStreak = 0
	if c.NotifyRecovery {
		return next, Decision{Send: true, Reason: "recovery"}
	}
	return next, Decision{Send: false, Reason: "recovery suppressed"}
}

func NewController(notifier Notifier, store Store, opts ControllerOptions) Controller {
	return Controller{
		Notifier:       notifier,
		Store:          store,
		MinSeverity:    strings.ToLower(strings.TrimSpace(opts.MinSeverity)),
		RepeatInterval: opts.RepeatInterval,
		NotifyRecovery: opts.NotifyRecovery,
		TriggerAfter:   thresholdOrDefault(opts.TriggerAfter),
		RecoveryAfter:  thresholdOrDefault(opts.RecoveryAfter),
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

func ValidateThreshold(name string, v int) error {
	if v < 1 {
		return fmt.Errorf("%s must be >= 1", name)
	}
	return nil
}

func thresholdOrDefault(v int) int {
	if v < 1 {
		return 1
	}
	return v
}

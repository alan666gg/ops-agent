package alerting

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
)

type AlertmanagerWebhook struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	TruncatedAlerts   int               `json:"truncatedAlerts"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

type ScopeResolver func(env string) string

func (w AlertmanagerWebhook) Reports(now time.Time, resolve ScopeResolver) []incident.Report {
	out := make([]incident.Report, 0, len(w.Alerts))
	for _, alert := range w.Alerts {
		out = append(out, buildReport(now, w, alert, resolve))
	}
	return out
}

func buildReport(now time.Time, webhook AlertmanagerWebhook, alert Alert, resolve ScopeResolver) incident.Report {
	labels := mergeMaps(webhook.CommonLabels, alert.Labels)
	annotations := mergeMaps(webhook.CommonAnnotations, alert.Annotations)
	envName := firstNonEmpty(
		labels["env"],
		labels["environment"],
		labels["cluster"],
		labels["namespace"],
		"unknown",
	)
	project := firstNonEmpty(labels["project"])
	if project == "" && resolve != nil {
		project = strings.TrimSpace(resolve(envName))
	}
	project = defaultProject(project)
	fingerprint := strings.TrimSpace(alert.Fingerprint)
	if fingerprint == "" {
		fingerprint = hashLabels(labels)
	}
	alertName := firstNonEmpty(labels["alertname"], "alert")
	severity := strings.ToLower(strings.TrimSpace(firstNonEmpty(labels["severity"], labels["level"], labels["priority"])))
	status := mapAlertStatus(strings.TrimSpace(alert.Status), severity)
	message := strings.TrimSpace(firstNonEmpty(
		annotations["summary"],
		annotations["message"],
		annotations["description"],
		buildFallbackSummary(alertName, labels),
	))
	result := checks.Result{
		Name:     "alertmanager_" + sanitize(alertName),
		Code:     strings.ToUpper(strings.ReplaceAll(firstNonEmpty(severity, alert.Status, "alert"), "-", "_")),
		Message:  message,
		Severity: severityForStatus(status),
	}
	report := incident.Report{
		Source:      "alertmanager",
		Key:         fingerprint,
		Project:     project,
		Env:         envName,
		Status:      status,
		Summary:     fmt.Sprintf("alertmanager %s %s: %s", envName, alertName, message),
		Fingerprint: fingerprint,
		TriggeredAt: pickTriggeredAt(now, alert),
		Results:     []checks.Result{result},
		TotalChecks: 1,
	}
	switch status {
	case "fail":
		report.FailCount = 1
		report.FailedChecks = []checks.Result{result}
	case "warn":
		report.WarnCount = 1
		report.WarningChecks = []checks.Result{result}
	}
	report.Highlights = buildHighlights(alertName, severity, webhook.Receiver, labels, annotations, alert)
	return report
}

func buildHighlights(alertName, severity, receiver string, labels, annotations map[string]string, alert Alert) []string {
	var out []string
	head := []string{"alertname=" + alertName}
	if strings.TrimSpace(severity) != "" {
		head = append(head, "severity="+severity)
	}
	if strings.TrimSpace(receiver) != "" {
		head = append(head, "receiver="+strings.TrimSpace(receiver))
	}
	out = append(out, strings.Join(head, " "))
	if instance := strings.TrimSpace(firstNonEmpty(labels["instance"], labels["pod"], labels["service"], labels["job"])); instance != "" {
		out = append(out, "target="+instance)
	}
	if summary := strings.TrimSpace(firstNonEmpty(annotations["summary"], annotations["description"])); summary != "" {
		out = append(out, summary)
	}
	if runbook := strings.TrimSpace(firstNonEmpty(annotations["runbook_url"], annotations["dashboard_url"])); runbook != "" {
		out = append(out, runbook)
	}
	if strings.TrimSpace(alert.GeneratorURL) != "" {
		out = append(out, alert.GeneratorURL)
	}
	return out
}

func mapAlertStatus(alertStatus, severity string) string {
	if strings.EqualFold(strings.TrimSpace(alertStatus), "resolved") {
		return "ok"
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "warning", "warn", "ticket", "info", "low":
		return "warn"
	case "critical", "error", "fatal", "page", "high":
		return "fail"
	default:
		return "fail"
	}
}

func severityForStatus(status string) checks.Severity {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "warn":
		return checks.SeverityWarn
	case "fail":
		return checks.SeverityFail
	default:
		return checks.SeverityPass
	}
}

func pickTriggeredAt(now time.Time, alert Alert) time.Time {
	if !alert.StartsAt.IsZero() {
		return alert.StartsAt.UTC()
	}
	return now.UTC()
}

func buildFallbackSummary(alertName string, labels map[string]string) string {
	target := firstNonEmpty(labels["instance"], labels["pod"], labels["service"], labels["job"])
	if strings.TrimSpace(target) != "" {
		return alertName + " on " + strings.TrimSpace(target)
	}
	return alertName
}

func hashLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "unknown"
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(strings.TrimSpace(labels[key]))
		b.WriteByte('\n')
	}
	sum := sha1.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func mergeMaps(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range base {
		out[key] = strings.TrimSpace(value)
	}
	for key, value := range extra {
		out[key] = strings.TrimSpace(value)
	}
	return out
}

func sanitize(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "alert"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('_')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "alert"
	}
	return out
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func defaultProject(project string) string {
	project = strings.TrimSpace(project)
	if project == "" {
		return "default"
	}
	return project
}

package chatops

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
)

type Command struct {
	Name       string
	Env        string
	Minutes    int
	RequestID  string
	IncidentID string
	Status     string
	Action     string
	TargetHost string
	Args       []string
	Reason     string
	Owner      string
}

func ParseCommand(text string) (Command, error) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return Command{}, fmt.Errorf("empty command")
	}
	cmd := strings.TrimPrefix(fields[0], "/")
	if idx := strings.IndexByte(cmd, '@'); idx >= 0 {
		cmd = cmd[:idx]
	}
	out := Command{Name: strings.ToLower(cmd), Minutes: 60}

	switch out.Name {
	case "start", "help", "pending", "reset":
		return out, nil
	case "active":
		if len(fields) > 1 {
			out.Env = fields[1]
		}
		return out, nil
	case "incident":
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /incident <incident_id>")
		}
		out.IncidentID = fields[1]
		return out, nil
	case "show":
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /show <request_id>")
		}
		out.RequestID = fields[1]
		return out, nil
	case "requests":
		out.Status = "pending"
		if len(fields) > 1 {
			out.Status = strings.ToLower(strings.TrimSpace(fields[1]))
		}
		return out, nil
	case "health":
		if len(fields) > 1 {
			out.Env = fields[1]
		} else {
			out.Env = "test"
		}
		return out, nil
	case "incidents":
		if len(fields) > 1 {
			v, err := strconv.Atoi(fields[1])
			if err != nil || v <= 0 {
				return Command{}, fmt.Errorf("minutes must be a positive integer")
			}
			out.Minutes = v
		}
		return out, nil
	case "approve":
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /approve <request_id>")
		}
		out.RequestID = fields[1]
		return out, nil
	case "reject":
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /reject <request_id> [reason]")
		}
		out.RequestID = fields[1]
		if len(fields) > 2 {
			out.Reason = strings.Join(fields[2:], " ")
		}
		if out.Reason == "" {
			out.Reason = "rejected from telegram"
		}
		return out, nil
	case "ack":
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /ack <incident_id> [note]")
		}
		out.IncidentID = fields[1]
		if len(fields) > 2 {
			out.Reason = strings.Join(fields[2:], " ")
		}
		return out, nil
	case "assign":
		if len(fields) < 3 {
			return Command{}, fmt.Errorf("usage: /assign <incident_id> <owner> [note]")
		}
		out.IncidentID = fields[1]
		out.Owner = fields[2]
		if len(fields) > 3 {
			out.Reason = strings.Join(fields[3:], " ")
		}
		return out, nil
	case "request":
		if len(fields) < 3 {
			return Command{}, fmt.Errorf("usage: /request <env> <action> [--target-host=name] [args...]")
		}
		out.Env = fields[1]
		out.Action = fields[2]
		for _, field := range fields[3:] {
			if strings.HasPrefix(field, "--target-host=") {
				out.TargetHost = strings.TrimPrefix(field, "--target-host=")
				continue
			}
			out.Args = append(out.Args, field)
		}
		return out, nil
	default:
		return Command{}, fmt.Errorf("unknown command %q", out.Name)
	}
}

func HelpText() string {
	return strings.Join([]string{
		"ops-agent Telegram commands:",
		"/help",
		"/reset",
		"/health <env>",
		"/incidents [minutes]",
		"/pending",
		"/active [env]",
		"/incident <incident_id>",
		"/requests [status]",
		"/show <request_id>",
		"/ack <incident_id> [note]",
		"/assign <incident_id> <owner> [note]",
		"/request <env> <action> [--target-host=name] [args...]",
		"/approve <request_id>",
		"/reject <request_id> [reason]",
	}, "\n")
}

func FormatHealth(resp HealthResponse) string {
	lines := []string{
		fmt.Sprintf("[%s] %s", strings.ToUpper(resp.Status), resp.Summary),
	}
	if strings.TrimSpace(resp.Project) != "" {
		lines = append(lines, "- project "+resp.Project)
	}
	for i, item := range resp.Highlights {
		if i >= 4 {
			break
		}
		lines = append(lines, "- highlight "+trimForChat(item, 140))
	}
	appendResults := func(prefix string, items []checks.Result, limit int) {
		count := 0
		for _, item := range items {
			lines = append(lines, fmt.Sprintf("- %s %s [%s]: %s", prefix, item.Name, item.Code, trimForChat(item.Message, 140)))
			count++
			if count >= limit {
				break
			}
		}
	}
	var fails, warns []checks.Result
	for _, item := range resp.Results {
		switch item.Severity {
		case checks.SeverityFail:
			fails = append(fails, item)
		case checks.SeverityWarn:
			warns = append(warns, item)
		}
	}
	appendResults("fail", fails, 5)
	appendResults("warn", warns, 5)
	for i, item := range resp.SuppressedChecks {
		if i >= 3 {
			lines = append(lines, fmt.Sprintf("- suppressed ... and %d more", len(resp.SuppressedChecks)-i))
			break
		}
		lines = append(lines, fmt.Sprintf("- suppressed %s by %s", item.Result.Name, item.SuppressedBy))
	}
	for i, item := range resp.Suggestions {
		if i >= 3 {
			lines = append(lines, fmt.Sprintf("- suggestions ... and %d more", len(resp.Suggestions)-i))
			break
		}
		line := "- suggest " + item.Action
		if item.TargetHost != "" {
			line += " target=" + item.TargetHost
		}
		if len(item.Args) > 0 {
			line += " args=" + strings.Join(item.Args, ",")
		}
		if item.RequiresApproval {
			line += " approval_required"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func FormatIncidentSummary(summary IncidentSummary) string {
	lines := []string{
		fmt.Sprintf("incident summary last %d minutes", summary.WindowMinutes),
		fmt.Sprintf("- total events: %d", summary.Total),
		fmt.Sprintf("- by status: %s", formatStatusMap(summary.ByStatus)),
	}
	if len(summary.Projects) > 0 {
		lines = append(lines, "- projects: "+strings.Join(summary.Projects, ","))
	}
	for i, target := range summary.TopTargets {
		if i >= 5 {
			break
		}
		lines = append(lines, "- top target: "+target)
	}
	return strings.Join(lines, "\n")
}

func FormatPending(resp PendingResponse) string {
	if len(resp.Items) == 0 {
		return "no pending approvals"
	}
	lines := []string{fmt.Sprintf("pending approvals: %d", resp.Count)}
	for i, item := range resp.Items {
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("... and %d more", len(resp.Items)-i))
			break
		}
		lines = append(lines, FormatPendingItem(item))
	}
	return strings.Join(lines, "\n")
}

func FormatActionList(resp ActionListResponse) string {
	if len(resp.Items) == 0 {
		return "no actions found"
	}
	lines := []string{fmt.Sprintf("actions status=%s count=%d", defaultString(resp.Status, "pending"), resp.Count)}
	for i, item := range resp.Items {
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("... and %d more", len(resp.Items)-i))
			break
		}
		lines = append(lines, FormatPendingItem(item))
	}
	if strings.TrimSpace(resp.NextCursor) != "" {
		lines = append(lines, "next_cursor="+resp.NextCursor)
	}
	return strings.Join(lines, "\n")
}

func FormatActiveIncidents(resp IncidentListResponse) string {
	if len(resp.Items) == 0 {
		return "no active incidents"
	}
	lines := []string{fmt.Sprintf("active incidents: %d", resp.Count)}
	for i, item := range resp.Items {
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("... and %d more", len(resp.Items)-i))
			break
		}
		lines = append(lines, FormatIncidentItem(item))
	}
	return strings.Join(lines, "\n")
}

func FormatIncidentDetail(item incident.Record) string {
	lines := []string{
		fmt.Sprintf("incident %s", item.ID),
		fmt.Sprintf("- status=%s", item.Status),
		fmt.Sprintf("- project=%s", defaultString(item.Project, "default")),
		fmt.Sprintf("- env=%s", defaultString(item.Env, "test")),
		fmt.Sprintf("- source=%s", defaultString(item.Source, "unknown")),
	}
	if strings.TrimSpace(item.Owner) != "" {
		lines = append(lines, "- owner="+item.Owner)
	}
	if item.Acknowledged {
		lines = append(lines, "- acknowledged_by="+item.AcknowledgedBy)
	}
	if strings.TrimSpace(item.Summary) != "" {
		lines = append(lines, "- summary="+trimForChat(item.Summary, 200))
	}
	for i, highlight := range item.Highlights {
		if i >= 3 {
			break
		}
		lines = append(lines, "- highlight "+trimForChat(highlight, 160))
	}
	if strings.TrimSpace(item.Note) != "" {
		lines = append(lines, "- note="+trimForChat(item.Note, 160))
	}
	return strings.Join(lines, "\n")
}

func FormatActionDetail(item approval.Request) string {
	lines := []string{
		fmt.Sprintf("request %s", item.ID),
		fmt.Sprintf("- status=%s", item.Status),
		fmt.Sprintf("- action=%s", item.Action),
		fmt.Sprintf("- project=%s", defaultString(item.Project, "default")),
		fmt.Sprintf("- env=%s", defaultString(item.Env, "test")),
	}
	if item.TargetHost != "" {
		lines = append(lines, "- target="+item.TargetHost)
	}
	if len(item.Args) > 0 {
		lines = append(lines, "- args="+strings.Join(item.Args, ","))
	}
	if item.Actor != "" {
		lines = append(lines, "- actor="+item.Actor)
	}
	if item.Approver != "" {
		lines = append(lines, "- approver="+item.Approver)
	}
	if strings.TrimSpace(item.Result) != "" {
		lines = append(lines, "- result="+trimForChat(item.Result, 200))
	}
	return strings.Join(lines, "\n")
}

func FormatIncidentItem(item incident.Record) string {
	line := fmt.Sprintf("%s [%s] project=%s env=%s", item.ID, strings.ToUpper(item.Status), defaultString(item.Project, "default"), defaultString(item.Env, "test"))
	if strings.TrimSpace(item.Owner) != "" {
		line += " owner=" + item.Owner
	}
	if item.Acknowledged {
		line += " acked_by=" + item.AcknowledgedBy
	}
	if strings.TrimSpace(item.Summary) != "" {
		line += " summary=" + trimForChat(item.Summary, 100)
	}
	return line
}

func FormatPendingItem(item approval.Request) string {
	line := fmt.Sprintf("%s %s project=%s env=%s", item.ID, item.Action, defaultString(item.Project, "default"), defaultString(item.Env, "test"))
	if item.TargetHost != "" {
		line += " target=" + item.TargetHost
	}
	if len(item.Args) > 0 {
		line += " args=" + strings.Join(item.Args, ",")
	}
	if item.Actor != "" {
		line += " actor=" + item.Actor
	}
	return line
}

func trimForChat(v string, limit int) string {
	v = strings.TrimSpace(v)
	if limit <= 0 || len(v) <= limit {
		return v
	}
	if limit < 4 {
		return v[:limit]
	}
	return v[:limit-3] + "..."
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func formatStatusMap(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := []string{"fail", "warn", "ok", "pass", "pending", "executed", "denied"}
	var parts []string
	seen := map[string]bool{}
	for _, key := range keys {
		if n, ok := m[key]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", key, n))
			seen[key] = true
		}
	}
	for key, n := range m {
		if seen[key] {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", key, n))
	}
	return strings.Join(parts, " ")
}

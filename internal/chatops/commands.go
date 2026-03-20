package chatops

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
	promapi "github.com/alan666gg/ops-agent/internal/prometheus"
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
	Query      string
	Step       time.Duration
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
	case "stats":
		if len(fields) > 1 {
			out.Env = fields[1]
		}
		return out, nil
	case "changes":
		out.Minutes = 120
		switch len(fields) {
		case 1:
			return out, nil
		case 2:
			if v, err := strconv.Atoi(fields[1]); err == nil {
				if v <= 0 {
					return Command{}, fmt.Errorf("minutes must be a positive integer")
				}
				out.Minutes = v
				return out, nil
			}
			out.Env = fields[1]
			return out, nil
		default:
			out.Env = fields[1]
			v, err := strconv.Atoi(fields[2])
			if err != nil || v <= 0 {
				return Command{}, fmt.Errorf("minutes must be a positive integer")
			}
			out.Minutes = v
			return out, nil
		}
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
	case "timeline":
		out.Minutes = 90
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /timeline <incident_id> [minutes]")
		}
		out.IncidentID = fields[1]
		if len(fields) > 2 {
			v, err := strconv.Atoi(fields[2])
			if err != nil || v <= 0 {
				return Command{}, fmt.Errorf("minutes must be a positive integer")
			}
			out.Minutes = v
		}
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
	case "promql":
		if len(fields) < 3 {
			return Command{}, fmt.Errorf("usage: /promql <env> [--minutes=30] [--step=60s] <query>")
		}
		out.Minutes = 0
		out.Env = fields[1]
		queryFields := make([]string, 0, len(fields)-2)
		for _, field := range fields[2:] {
			switch {
			case strings.HasPrefix(field, "--minutes="):
				v, err := strconv.Atoi(strings.TrimPrefix(field, "--minutes="))
				if err != nil || v < 0 {
					return Command{}, fmt.Errorf("minutes must be a non-negative integer")
				}
				out.Minutes = v
			case strings.HasPrefix(field, "--step="):
				d, err := time.ParseDuration(strings.TrimPrefix(field, "--step="))
				if err != nil || d <= 0 {
					return Command{}, fmt.Errorf("step must be a positive duration")
				}
				out.Step = d
			default:
				queryFields = append(queryFields, field)
			}
		}
		out.Query = strings.TrimSpace(strings.Join(queryFields, " "))
		if out.Query == "" {
			return Command{}, fmt.Errorf("usage: /promql <env> [--minutes=30] [--step=60s] <query>")
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
	case "unsilence":
		if len(fields) < 2 {
			return Command{}, fmt.Errorf("usage: /unsilence <incident_id> [note]")
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
		"/promql <env> [--minutes=30] [--step=60s] <query>",
		"/stats [env]",
		"/changes [env] [minutes]",
		"/incidents [minutes]",
		"/pending",
		"/active [env]",
		"/incident <incident_id>",
		"/timeline <incident_id> [minutes]",
		"/requests [status]",
		"/show <request_id>",
		"/ack <incident_id> [note]",
		"/unsilence <incident_id> [note]",
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

func FormatPrometheusQuery(resp PrometheusQueryResponse) string {
	lines := []string{
		fmt.Sprintf("prometheus env=%s project=%s", defaultString(resp.Env, "test"), defaultString(resp.Project, "default")),
		"- " + trimForChat(resp.Data.Summary, 200),
		"- query=" + trimForChat(resp.Data.Query, 160),
		"- result_type=" + resp.Data.ResultType,
	}
	if len(resp.Data.Warnings) > 0 {
		lines = append(lines, "- warning="+trimForChat(resp.Data.Warnings[0], 160))
	}
	switch resp.Data.ResultType {
	case "vector":
		for i, item := range resp.Data.Series {
			if i >= 5 {
				lines = append(lines, fmt.Sprintf("- series ... and %d more", len(resp.Data.Series)-i))
				break
			}
			lines = append(lines, "- "+formatPrometheusSeries(item))
		}
	case "matrix":
		for i, item := range resp.Data.Series {
			if i >= 5 {
				lines = append(lines, fmt.Sprintf("- series ... and %d more", len(resp.Data.Series)-i))
				break
			}
			lines = append(lines, "- "+formatPrometheusSeries(item))
		}
	case "scalar":
		if resp.Data.Scalar != nil {
			lines = append(lines, fmt.Sprintf("- scalar %s @ %s", resp.Data.Scalar.Value, resp.Data.Scalar.Time.UTC().Format("15:04:05")))
		}
	case "string":
		if resp.Data.String != nil {
			lines = append(lines, fmt.Sprintf("- string %s @ %s", trimForChat(resp.Data.String.Value, 160), resp.Data.String.Time.UTC().Format("15:04:05")))
		}
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

func FormatIncidentStats(resp IncidentStatsResponse) string {
	lines := []string{
		"incident stats",
		fmt.Sprintf("- total=%d open=%d resolved=%d", resp.Summary.TotalRecords, resp.Summary.OpenRecords, resp.Summary.ResolvedRecords),
		fmt.Sprintf("- acknowledged=%d assigned=%d silenced=%d", resp.Summary.AcknowledgedRecords, resp.Summary.AssignedRecords, resp.Summary.SilencedRecords),
		fmt.Sprintf("- reopen=%d resolved_cycles=%d ack_events=%d", resp.Summary.ReopenCount, resp.Summary.ResolutionCount, resp.Summary.AckCount),
		fmt.Sprintf("- avg_mtta=%.1fs avg_mttr=%.1fs", resp.Summary.AvgMTTASeconds, resp.Summary.AvgMTTRSeconds),
	}
	if strings.TrimSpace(resp.Env) != "" {
		lines = append(lines, "- env="+resp.Env)
	}
	if len(resp.Projects) > 0 {
		lines = append(lines, "- projects="+strings.Join(resp.Projects, ","))
	}
	if resp.Summary.OldestOpenAgeSeconds > 0 {
		lines = append(lines, fmt.Sprintf("- oldest_open_age=%.1fs", resp.Summary.OldestOpenAgeSeconds))
	}
	for i, scope := range resp.Scopes {
		if i >= 6 {
			lines = append(lines, fmt.Sprintf("- scopes ... and %d more", len(resp.Scopes)-i))
			break
		}
		lines = append(lines, fmt.Sprintf("- scope project=%s env=%s source=%s open=%d silenced=%d mtta=%.1fs mttr=%.1fs", defaultString(scope.Project, "default"), defaultString(scope.Env, "test"), defaultString(scope.Source, "unknown"), scope.Stats.OpenRecords, scope.Stats.SilencedRecords, scope.Stats.AvgMTTASeconds, scope.Stats.AvgMTTRSeconds))
	}
	return strings.Join(lines, "\n")
}

func FormatRecentChanges(resp RecentChangesResponse) string {
	lines := []string{
		fmt.Sprintf("recent changes last %d minutes", resp.WindowMinutes),
		fmt.Sprintf("- count=%d", resp.Count),
	}
	if strings.TrimSpace(resp.Env) != "" {
		lines = append(lines, "- env="+resp.Env)
	}
	if len(resp.Projects) > 0 {
		lines = append(lines, "- projects="+strings.Join(resp.Projects, ","))
	}
	if len(resp.Items) == 0 {
		lines = append(lines, "- no recent deploy or change events found")
		return strings.Join(lines, "\n")
	}
	for i, item := range resp.Items {
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("- changes ... and %d more", len(resp.Items)-i))
			break
		}
		lines = append(lines, "- "+formatTimelineEntry(item))
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
	now := time.Now().UTC()
	state := "open"
	if !item.Open {
		state = "resolved"
	}
	lines := []string{
		fmt.Sprintf("incident %s", item.ID),
		fmt.Sprintf("- status=%s", item.Status),
		fmt.Sprintf("- state=%s", state),
		fmt.Sprintf("- project=%s", defaultString(item.Project, "default")),
		fmt.Sprintf("- env=%s", defaultString(item.Env, "test")),
		fmt.Sprintf("- source=%s", defaultString(item.Source, "unknown")),
	}
	if !item.ClosedAt.IsZero() {
		lines = append(lines, "- resolved_at="+item.ClosedAt.UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(item.Owner) != "" {
		lines = append(lines, "- owner="+item.Owner)
	}
	if item.Acknowledged {
		lines = append(lines, "- acknowledged_by="+item.AcknowledgedBy)
	}
	if externalLine := formatExternalAlert(item.External); externalLine != "" {
		lines = append(lines, "- "+externalLine)
	}
	if silenceLine := formatIncidentSilence(item.Silence, now); silenceLine != "" {
		lines = append(lines, "- "+silenceLine)
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

func FormatIncidentDetailWithChanges(item incident.Record, changes RecentChangesResponse) string {
	lines := strings.Split(FormatIncidentDetail(item), "\n")
	if len(changes.Items) == 0 {
		return strings.Join(lines, "\n")
	}
	lines = append(lines, fmt.Sprintf("- recent changes last %d minutes:", changes.WindowMinutes))
	for i, change := range changes.Items {
		if i >= 3 {
			lines = append(lines, fmt.Sprintf("  ... and %d more", len(changes.Items)-i))
			break
		}
		lines = append(lines, "  "+formatTimelineEntry(change))
	}
	return strings.Join(lines, "\n")
}

func FormatIncidentTimeline(timeline incident.Timeline) string {
	now := time.Now().UTC()
	state := "open"
	if !timeline.Incident.Open {
		state = "resolved"
	}
	lines := []string{
		fmt.Sprintf("timeline %s last %d minutes", timeline.Incident.ID, timeline.WindowMinutes),
		fmt.Sprintf("- status=%s", timeline.Incident.Status),
		fmt.Sprintf("- state=%s", state),
		fmt.Sprintf("- project=%s", defaultString(timeline.Incident.Project, "default")),
		fmt.Sprintf("- env=%s", defaultString(timeline.Incident.Env, "test")),
	}
	if !timeline.Incident.ClosedAt.IsZero() {
		lines = append(lines, "- resolved_at="+timeline.Incident.ClosedAt.UTC().Format(time.RFC3339))
	}
	if silenceLine := formatIncidentSilence(timeline.Incident.Silence, now); silenceLine != "" {
		lines = append(lines, "- "+silenceLine)
	}
	for i, item := range timeline.CorrelatedChanges {
		if i >= 3 {
			lines = append(lines, fmt.Sprintf("- correlated changes ... and %d more", len(timeline.CorrelatedChanges)-i))
			break
		}
		lines = append(lines, "- correlated "+formatTimelineEntry(item))
	}
	if len(timeline.Entries) == 0 {
		lines = append(lines, "- no audit events found in this window")
		return strings.Join(lines, "\n")
	}
	lines = append(lines, "- events:")
	for i, item := range timeline.Entries {
		if i >= 12 {
			lines = append(lines, fmt.Sprintf("... and %d more events", len(timeline.Entries)-i))
			break
		}
		lines = append(lines, "  "+formatTimelineEntry(item))
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
	if silence := formatIncidentSilenceCompact(item.Silence, time.Now().UTC()); silence != "" {
		line += " " + silence
	}
	if !item.Open && !item.ClosedAt.IsZero() {
		line += " resolved"
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

func formatTimelineEntry(item incident.TimelineEntry) string {
	parts := []string{item.Time.UTC().Format("15:04"), item.Kind}
	if strings.TrimSpace(item.Action) != "" {
		parts = append(parts, item.Action)
	}
	if strings.TrimSpace(item.Status) != "" {
		parts = append(parts, "["+item.Status+"]")
	}
	if strings.TrimSpace(item.Actor) != "" {
		parts = append(parts, "by="+item.Actor)
	}
	if strings.TrimSpace(item.TargetHost) != "" {
		parts = append(parts, "host="+item.TargetHost)
	}
	if strings.TrimSpace(item.Target) != "" {
		parts = append(parts, "target="+trimForChat(item.Target, 60))
	}
	if strings.TrimSpace(item.Reference) != "" {
		parts = append(parts, "ref="+trimForChat(item.Reference, 40))
	}
	if strings.TrimSpace(item.Revision) != "" {
		parts = append(parts, "rev="+trimForChat(item.Revision, 16))
	}
	if strings.TrimSpace(item.URL) != "" {
		parts = append(parts, "link="+trimForChat(item.URL, 72))
	}
	if strings.TrimSpace(item.Message) != "" {
		parts = append(parts, trimForChat(item.Message, 90))
	}
	if item.LikelyChange {
		parts = append(parts, "likely_change")
	}
	return strings.Join(parts, " ")
}

func formatPrometheusSeries(item promapi.Series) string {
	metric := formatPrometheusMetric(item.Metric)
	switch {
	case item.Value != nil:
		if metric == "" {
			return item.Value.Value
		}
		return metric + " value=" + item.Value.Value
	case len(item.Values) > 0:
		last := item.Values[len(item.Values)-1]
		if metric == "" {
			return fmt.Sprintf("last=%s samples=%d", last.Value, len(item.Values))
		}
		return fmt.Sprintf("%s last=%s samples=%d", metric, last.Value, len(item.Values))
	case metric != "":
		return metric
	default:
		return "(empty series)"
	}
}

func formatPrometheusMetric(metric map[string]string) string {
	if len(metric) == 0 {
		return ""
	}
	keys := make([]string, 0, len(metric))
	for key := range metric {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+metric[key])
	}
	return strings.Join(parts, ",")
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

func formatExternalAlert(ext *incident.ExternalAlert) string {
	if ext == nil {
		return ""
	}
	parts := []string{"external=" + defaultString(ext.Provider, "unknown")}
	if strings.TrimSpace(ext.AlertName) != "" {
		parts = append(parts, "alert="+ext.AlertName)
	}
	if strings.TrimSpace(ext.Receiver) != "" {
		parts = append(parts, "receiver="+ext.Receiver)
	}
	for _, key := range []string{"instance", "pod", "service", "job"} {
		if value := strings.TrimSpace(ext.Labels[key]); value != "" {
			parts = append(parts, "target="+value)
			break
		}
	}
	return strings.Join(parts, " ")
}

func formatIncidentSilence(silence *incident.ExternalSilence, now time.Time) string {
	if silence == nil {
		return ""
	}
	parts := []string{"silence=" + incident.SilenceStatus(silence, now)}
	if strings.TrimSpace(silence.ID) != "" {
		parts = append(parts, "id="+silence.ID)
	}
	if !silence.EndsAt.IsZero() {
		parts = append(parts, "until="+silence.EndsAt.UTC().Format(time.RFC3339))
	}
	if !silence.ExpiredAt.IsZero() {
		parts = append(parts, "expired_at="+silence.ExpiredAt.UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, " ")
}

func formatIncidentSilenceCompact(silence *incident.ExternalSilence, now time.Time) string {
	if silence == nil {
		return ""
	}
	status := incident.SilenceStatus(silence, now)
	if strings.TrimSpace(silence.ID) == "" {
		return "silence=" + status
	}
	return "silence=" + status + ":" + silence.ID
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

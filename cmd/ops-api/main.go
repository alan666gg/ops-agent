package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/alerting"
	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	rbexec "github.com/alan666gg/ops-agent/internal/exec"
	"github.com/alan666gg/ops-agent/internal/incident"
	"github.com/alan666gg/ops-agent/internal/notify"
	"github.com/alan666gg/ops-agent/internal/policy"
	promapi "github.com/alan666gg/ops-agent/internal/prometheus"
	"github.com/alan666gg/ops-agent/internal/slo"
)

type approvalBackend interface {
	Create(r approval.Request) error
	Update(id string, update func(*approval.Request) error) (approval.Request, error)
	GetByID(id string) (approval.Request, error)
	ListPending(limit int, projects []string) ([]approval.Request, error)
	ListByStatus(status string, limit int, projects []string) ([]approval.Request, error)
	ExpirePendingOlderThan(ttl time.Duration) (int64, error)
}

type server struct {
	envFile       string
	policyFile    string
	auditDriver   string
	auditFile     string
	auditStore    audit.Store
	incidentStore incident.Store
	token         string
	alertToken    string
	changeToken   string
	alertAPIToken string
	syncAlertAck  bool
	alertSilence  time.Duration
	alertRefresh  time.Duration
	alertTimeout  time.Duration
	approvalStore approvalBackend
	metrics       *apiMetrics
	limiter       *rateLimiter
	notifyCtl     notify.Controller
	notifyMin     string
	mu            sync.Mutex
}

type apiMetrics struct {
	mu               sync.Mutex
	requestsTotal    map[string]int64
	errorsTotal      map[string]int64
	durationMsTotal  map[string]float64
	actionsTotal     map[string]int64
	actionsFailTotal map[string]int64
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type rateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	max      int
	requests map[string][]time.Time
}

var newPrometheusHTTPClient = func(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

var newAlertmanagerHTTPClient = func(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func newRateLimiter(window time.Duration, max int) *rateLimiter {
	if window <= 0 {
		window = 1 * time.Minute
	}
	if max <= 0 {
		max = 120
	}
	return &rateLimiter{window: window, max: max, requests: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	arr := l.requests[key]
	k := 0
	for _, t := range arr {
		if t.After(cutoff) {
			arr[k] = t
			k++
		}
	}
	arr = arr[:k]
	if len(arr) >= l.max {
		l.requests[key] = arr
		return false
	}
	arr = append(arr, now)
	l.requests[key] = arr
	return true
}

type actionRequest struct {
	Action     string   `json:"action"`
	Env        string   `json:"env,omitempty"`
	TargetHost string   `json:"target_host,omitempty"`
	Args       []string `json:"args"`
	Approved   bool     `json:"approved"`
	Actor      string   `json:"actor"`
	TimeoutS   int      `json:"timeout_seconds"`
}

type requestActionResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type approveRequest struct {
	RequestID string `json:"request_id"`
	Approver  string `json:"approver"`
	TimeoutS  int    `json:"timeout_seconds"`
}

type rejectRequest struct {
	RequestID string `json:"request_id"`
	Approver  string `json:"approver"`
	Reason    string `json:"reason"`
}

type actionResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
}

type incidentSummary struct {
	WindowMinutes int            `json:"window_minutes"`
	Projects      []string       `json:"projects,omitempty"`
	Total         int            `json:"total_events"`
	ByStatus      map[string]int `json:"by_status"`
	TopTargets    []string       `json:"top_targets"`
}

type incidentStatsResponse struct {
	Projects []string              `json:"projects,omitempty"`
	Env      string                `json:"env,omitempty"`
	Source   string                `json:"source,omitempty"`
	Summary  incident.Stats        `json:"summary"`
	Scopes   []incident.ScopeStats `json:"scopes,omitempty"`
}

type incidentActionRequest struct {
	ID    string `json:"id"`
	Actor string `json:"actor"`
	Owner string `json:"owner,omitempty"`
	Note  string `json:"note,omitempty"`
}

type alertmanagerReconcileRequest struct {
	ID      string `json:"id,omitempty"`
	Actor   string `json:"actor,omitempty"`
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
}

type alertmanagerReconcileItem struct {
	ID             string `json:"id"`
	Project        string `json:"project,omitempty"`
	Env            string `json:"env,omitempty"`
	SilenceID      string `json:"silence_id,omitempty"`
	PreviousStatus string `json:"previous_status,omitempty"`
	CurrentStatus  string `json:"current_status,omitempty"`
	Updated        bool   `json:"updated"`
	Message        string `json:"message,omitempty"`
}

type alertmanagerReconcileResponse struct {
	Status  string                      `json:"status"`
	Checked int                         `json:"checked"`
	Updated int                         `json:"updated"`
	Expired int                         `json:"expired"`
	Skipped int                         `json:"skipped"`
	Failed  int                         `json:"failed"`
	Items   []alertmanagerReconcileItem `json:"items,omitempty"`
}

type alertmanagerIngestResponse struct {
	Status string            `json:"status"`
	Count  int               `json:"count"`
	Items  []incident.Record `json:"items,omitempty"`
}

type changeEventRequest struct {
	OccurredAt time.Time `json:"occurred_at,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Action     string    `json:"action,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	Project    string    `json:"project,omitempty"`
	Env        string    `json:"env"`
	Target     string    `json:"target,omitempty"`
	TargetHost string    `json:"target_host,omitempty"`
	Status     string    `json:"status,omitempty"`
	Message    string    `json:"message"`
	Reference  string    `json:"reference,omitempty"`
	Revision   string    `json:"revision,omitempty"`
	URL        string    `json:"url,omitempty"`
}

type changesResponse struct {
	WindowMinutes int                      `json:"window_minutes"`
	Projects      []string                 `json:"projects,omitempty"`
	Env           string                   `json:"env,omitempty"`
	Count         int                      `json:"count"`
	Items         []incident.TimelineEntry `json:"items"`
}

type githubRepository struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	HTMLURL  string `json:"html_url"`
}

type githubSender struct {
	Login string `json:"login"`
}

type githubWorkflow struct {
	Name string `json:"name"`
}

type githubWorkflowRun struct {
	Name       string    `json:"name"`
	HeadBranch string    `json:"head_branch"`
	HeadSHA    string    `json:"head_sha"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	HTMLURL    string    `json:"html_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type githubDeployment struct {
	Environment string         `json:"environment"`
	SHA         string         `json:"sha"`
	Ref         string         `json:"ref"`
	Task        string         `json:"task"`
	Description string         `json:"description"`
	Payload     map[string]any `json:"payload"`
}

type githubDeploymentStatus struct {
	State          string    `json:"state"`
	Description    string    `json:"description"`
	EnvironmentURL string    `json:"environment_url"`
	LogURL         string    `json:"log_url"`
	TargetURL      string    `json:"target_url"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type githubChangeWebhook struct {
	Action           string                  `json:"action"`
	Repository       githubRepository        `json:"repository"`
	Sender           githubSender            `json:"sender"`
	Workflow         *githubWorkflow         `json:"workflow,omitempty"`
	WorkflowRun      *githubWorkflowRun      `json:"workflow_run,omitempty"`
	Deployment       *githubDeployment       `json:"deployment,omitempty"`
	DeploymentStatus *githubDeploymentStatus `json:"deployment_status,omitempty"`
}

type gitlabProject struct {
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	Name              string `json:"name"`
}

type gitlabVariable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type gitlabPipelineAttributes struct {
	ID             int              `json:"id"`
	Name           string           `json:"name"`
	Ref            string           `json:"ref"`
	SHA            string           `json:"sha"`
	Status         string           `json:"status"`
	DetailedStatus string           `json:"detailed_status"`
	Source         string           `json:"source"`
	URL            string           `json:"url"`
	Stages         []string         `json:"stages"`
	Variables      []gitlabVariable `json:"variables"`
	CreatedAt      string           `json:"created_at"`
	FinishedAt     string           `json:"finished_at"`
}

type gitlabReleaseAttributes struct {
	Name       string    `json:"name"`
	Tag        string    `json:"tag"`
	Action     string    `json:"action"`
	ReleasedAt time.Time `json:"released_at"`
}

type gitlabChangeWebhook struct {
	ObjectKind       string                   `json:"object_kind"`
	EventName        string                   `json:"event_name"`
	UserName         string                   `json:"user_name"`
	Ref              string                   `json:"ref"`
	CheckoutSHA      string                   `json:"checkout_sha"`
	BeforeSHA        string                   `json:"before_sha"`
	After            string                   `json:"after"`
	Project          gitlabProject            `json:"project"`
	ObjectAttributes gitlabPipelineAttributes `json:"object_attributes"`
	Release          gitlabReleaseAttributes  `json:"release"`
}

func main() {
	addr := flag.String("addr", ":8090", "http listen addr")
	envFile := flag.String("env-file", "configs/environments.yaml", "path to environments yaml")
	policyFile := flag.String("policy", "configs/policies.yaml", "path to policy yaml")
	auditFile := flag.String("audit", "audit/api.jsonl", "audit output jsonl")
	auditDriver := flag.String("audit-driver", "jsonl", "audit store driver: jsonl|sqlite")
	incidentStateFile := flag.String("incident-state-file", "audit/incidents.db", "sqlite state file for open incidents and ownership")
	pendingFile := flag.String("pending-file", "audit/pending-actions.db", "pending approval requests store path")
	pendingDriver := flag.String("pending-driver", "sqlite", "pending store driver: sqlite|json")
	pendingTTL := flag.Duration("pending-ttl", 24*time.Hour, "expire pending requests older than this duration (0 to disable)")
	rateLimitWindow := flag.Duration("rate-limit-window", time.Minute, "rate limit window")
	rateLimitMax := flag.Int("rate-limit-max", 120, "max requests per client per window")
	notifyWebhook := flag.String("notify-webhook", "", "generic webhook URL for health incident notifications")
	slackWebhook := flag.String("notify-slack-webhook", "", "Slack incoming webhook URL for health incident notifications")
	telegramBotToken := flag.String("notify-telegram-bot-token", "", "Telegram bot token for health incident notifications")
	telegramChatID := flag.String("notify-telegram-chat-id", "", "Telegram chat id for health incident notifications")
	notifyMin := flag.String("notify-min-severity", "warn", "minimum health status to notify: warn|fail")
	notifyStateFile := flag.String("notify-state-file", "audit/notify-state.db", "notification dedupe state sqlite file")
	notifyRepeat := flag.Duration("notify-repeat", 30*time.Minute, "repeat identical incident notifications after this interval")
	notifyRecovery := flag.Bool("notify-recovery", true, "send notification when an incident recovers below the notify threshold")
	notifyTriggerAfter := flag.Int("notify-trigger-after", 1, "open an incident only after this many consecutive unhealthy cycles")
	notifyRecoveryAfter := flag.Int("notify-recovery-after", 1, "close an incident only after this many consecutive healthy cycles")
	notifyConfigFile := flag.String("notify-config", "", "notification routing config file (replaces direct notifier flags)")
	token := flag.String("token", os.Getenv("OPS_API_TOKEN"), "api bearer token (or OPS_API_TOKEN env)")
	alertToken := flag.String("alert-token", os.Getenv("OPS_ALERT_TOKEN"), "dedicated bearer/shared token for /alerts/alertmanager (or OPS_ALERT_TOKEN env)")
	changeToken := flag.String("change-token", os.Getenv("OPS_CHANGE_TOKEN"), "dedicated bearer/shared token for /changes/* webhook ingestion (or OPS_CHANGE_TOKEN env)")
	alertAPIToken := flag.String("alertmanager-api-token", os.Getenv("OPS_ALERTMANAGER_API_TOKEN"), "optional bearer token used when syncing Alertmanager silences")
	syncAlertAck := flag.Bool("alertmanager-sync-ack", false, "when true, acknowledging an Alertmanager-backed incident also creates a silence in Alertmanager")
	alertSilence := flag.Duration("alertmanager-silence-duration", 2*time.Hour, "silence duration used when --alertmanager-sync-ack is enabled")
	alertRefresh := flag.Duration("alertmanager-refresh-interval", 5*time.Minute, "when >0, periodically refresh stored Alertmanager silence state back into local incidents")
	alertTimeout := flag.Duration("alertmanager-refresh-timeout", 15*time.Second, "timeout used for one Alertmanager silence refresh cycle")
	flag.Parse()
	if err := notify.ValidateMinSeverity(*notifyMin); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := notify.ValidateThreshold("notify-trigger-after", *notifyTriggerAfter); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := notify.ValidateThreshold("notify-recovery-after", *notifyRecoveryAfter); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if strings.TrimSpace(*notifyConfigFile) != "" && (strings.TrimSpace(*notifyWebhook) != "" || strings.TrimSpace(*slackWebhook) != "" || strings.TrimSpace(*telegramBotToken) != "" || strings.TrimSpace(*telegramChatID) != "") {
		fmt.Println("use either --notify-config or direct notifier flags, not both")
		os.Exit(1)
	}

	store, err := newApprovalBackend(*pendingDriver, *pendingFile)
	if err != nil {
		panic(err)
	}
	auditStore, err := audit.Open(*auditDriver, *auditFile)
	if err != nil {
		panic(err)
	}
	incidentStore := incident.NewSQLiteStore(*incidentStateFile)

	_ = os.MkdirAll("audit", 0o755)
	notifierImpl := notify.Build(*notifyWebhook, *slackWebhook, *telegramBotToken, *telegramChatID)
	var resolver notify.DeliveryResolver
	if strings.TrimSpace(*notifyConfigFile) != "" {
		routingCfg, err := notify.LoadRouting(*notifyConfigFile)
		if err != nil {
			fmt.Println("notification config invalid:", err)
			os.Exit(1)
		}
		resolver, err = routingCfg.BuildResolver()
		if err != nil {
			fmt.Println("notification config invalid:", err)
			os.Exit(1)
		}
	}
	s := &server{
		envFile:       *envFile,
		policyFile:    *policyFile,
		auditDriver:   strings.ToLower(strings.TrimSpace(*auditDriver)),
		auditFile:     *auditFile,
		auditStore:    auditStore,
		incidentStore: incidentStore,
		token:         strings.TrimSpace(*token),
		alertToken:    strings.TrimSpace(*alertToken),
		changeToken:   strings.TrimSpace(*changeToken),
		alertAPIToken: strings.TrimSpace(*alertAPIToken),
		syncAlertAck:  *syncAlertAck,
		alertSilence:  *alertSilence,
		alertRefresh:  *alertRefresh,
		alertTimeout:  *alertTimeout,
		approvalStore: store,
		limiter:       newRateLimiter(*rateLimitWindow, *rateLimitMax),
		notifyCtl: notify.NewController(notifierImpl, notify.NewSQLiteStore(*notifyStateFile), notify.ControllerOptions{
			MinSeverity:    *notifyMin,
			RepeatInterval: *notifyRepeat,
			NotifyRecovery: *notifyRecovery,
			TriggerAfter:   *notifyTriggerAfter,
			RecoveryAfter:  *notifyRecoveryAfter,
			Resolver:       resolver,
		}),
		notifyMin: strings.ToLower(strings.TrimSpace(*notifyMin)),
		metrics: &apiMetrics{
			requestsTotal:    map[string]int64{},
			errorsTotal:      map[string]int64{},
			durationMsTotal:  map[string]float64{},
			actionsTotal:     map[string]int64{},
			actionsFailTotal: map[string]int64{},
		},
	}

	if *pendingTTL > 0 {
		if n, err := s.approvalStore.ExpirePendingOlderThan(*pendingTTL); err == nil && n > 0 {
			fmt.Printf("expired pending requests: %d\n", n)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/run", s.handleRunHealth)
	mux.HandleFunc("/actions/run", s.handleRunAction)
	mux.HandleFunc("/actions/request", s.handleRequestAction)
	mux.HandleFunc("/actions/approve", s.handleApproveAction)
	mux.HandleFunc("/actions/reject", s.handleRejectAction)
	mux.HandleFunc("/actions/pending", s.handlePendingActions)
	mux.HandleFunc("/actions/get", s.handleGetAction)
	mux.HandleFunc("/actions/list", s.handleListActions)
	mux.HandleFunc("/audit/tail", s.handleTailAudit)
	mux.HandleFunc("/alerts/alertmanager", s.handleAlertmanagerWebhook)
	mux.HandleFunc("/prometheus/query", s.handlePrometheusQuery)
	mux.HandleFunc("/changes/events", s.handleChangeEvent)
	mux.HandleFunc("/changes/recent", s.handleRecentChanges)
	mux.HandleFunc("/changes/github", s.handleGitHubChangeWebhook)
	mux.HandleFunc("/changes/gitlab", s.handleGitLabChangeWebhook)
	mux.HandleFunc("/incidents/summary", s.handleIncidentSummary)
	mux.HandleFunc("/incidents/stats", s.handleIncidentStats)
	mux.HandleFunc("/incidents/active", s.handleActiveIncidents)
	mux.HandleFunc("/incidents/get", s.handleGetIncident)
	mux.HandleFunc("/incidents/timeline", s.handleIncidentTimeline)
	mux.HandleFunc("/incidents/ack", s.handleAckIncident)
	mux.HandleFunc("/incidents/unsilence", s.handleUnsilenceIncident)
	mux.HandleFunc("/incidents/assign", s.handleAssignIncident)
	mux.HandleFunc("/incidents/reconcile-alertmanager", s.handleReconcileAlertmanager)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "ops-api"})
	})

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		reqID := newID()
		sw.Header().Set("X-Request-ID", reqID)
		sw.Header().Set("Content-Type", "application/json")

		if !s.limiter.allow(clientIP(r)) {
			sw.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(sw).Encode(map[string]any{"error": "rate limit exceeded", "request_id": reqID})
			s.metricsRecord(r.URL.Path, sw.status, time.Since(start))
			return
		}

		if r.URL.Path != "/ready" && r.URL.Path != "/metrics" && !s.authorizedPath(r) {
			sw.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(sw).Encode(map[string]any{"error": "unauthorized", "request_id": reqID})
			s.metricsRecord(r.URL.Path, sw.status, time.Since(start))
			return
		}
		mux.ServeHTTP(sw, r)
		s.metricsRecord(r.URL.Path, sw.status, time.Since(start))
	})

	if s.alertRefresh > 0 && s.incidentStore != nil && s.auditStore != nil {
		go s.runAlertmanagerReconciler()
	}

	fmt.Println("ops-api listening on", *addr)
	fmt.Printf("approval store: driver=%s path=%s\n", *pendingDriver, *pendingFile)
	if s.token == "" {
		fmt.Println("warning: OPS API token is empty, endpoints are open (except /ready)")
	}
	if err := http.ListenAndServe(*addr, h); err != nil {
		panic(err)
	}
}

func newApprovalBackend(driver, path string) (approvalBackend, error) {
	d := strings.ToLower(strings.TrimSpace(driver))
	switch d {
	case "", "sqlite":
		return approval.SQLiteStore{Path: path}, nil
	case "json":
		return approval.Store{Path: path}, nil
	default:
		return nil, fmt.Errorf("unsupported pending-driver: %s", driver)
	}
}

func (s *server) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.token
	}
	return false
}

func (s *server) authorizedPath(r *http.Request) bool {
	if r.URL.Path == "/alerts/alertmanager" {
		return s.authorizedAlert(r) || s.authorized(r)
	}
	if r.URL.Path == "/changes/events" || r.URL.Path == "/changes/github" || r.URL.Path == "/changes/gitlab" {
		return s.authorizedChange(r) || s.authorized(r)
	}
	return s.authorized(r)
}

func (s *server) authorizedAlert(r *http.Request) bool {
	if s.alertToken == "" {
		return false
	}
	if got := strings.TrimSpace(r.Header.Get("X-Ops-Alert-Token")); got != "" {
		return got == s.alertToken
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.alertToken
	}
	return false
}

func (s *server) authorizedChange(r *http.Request) bool {
	if s.changeToken == "" {
		return false
	}
	if got := strings.TrimSpace(r.Header.Get("X-Ops-Change-Token")); got != "" {
		return got == s.changeToken
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.changeToken
	}
	return false
}

func (s *server) handleRunHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	envName := r.URL.Query().Get("env")
	if envName == "" {
		envName = "test"
	}

	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	env, ok := cfg.Environments[envName]
	if !ok {
		http.Error(w, `{"error":"env not found"}`, http.StatusNotFound)
		return
	}
	project := env.ProjectName()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := checks.NewRegistry(checks.CheckersForEnvironment(env)...).RunAll(ctx)
	for _, rs := range results {
		_ = s.auditStore.Append(audit.Event{
			Time:    time.Now().UTC(),
			Actor:   "ops-api",
			Action:  "health_run",
			Project: project,
			Env:     envName,
			Target:  envName + "/" + rs.Name,
			Status:  resultStatus(rs),
			Message: rs.Code + ": " + rs.Message,
		})
	}
	if sloResults, err := (slo.Evaluator{}).EvaluateAvailabilityStore(s.auditStore, project, envName, env); err == nil {
		results = append(results, sloResults...)
		for _, rs := range sloResults {
			_ = s.auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-api",
				Action:  "slo_eval",
				Project: project,
				Env:     envName,
				Target:  envName + "/" + rs.Name,
				Status:  resultStatus(rs),
				Message: rs.Code + ": " + rs.Message,
			})
		}
	} else {
		_ = s.auditStore.Append(audit.Event{
			Time:    time.Now().UTC(),
			Actor:   "ops-api",
			Action:  "slo_eval",
			Project: project,
			Env:     envName,
			Status:  "failed",
			Message: err.Error(),
		})
	}
	policyCfg, _ := policy.Load(s.policyFile)
	recentAutoActions, _ := s.auditStore.CountRecentAutoActions(project, envName, time.Now().UTC().Add(-time.Hour))
	recentChanges, _ := incident.RecentChanges(s.auditStore, project, envName, 2*time.Hour, 5)
	metricSignals, err := evaluatePrometheusSignals(r.Context(), envName, env)
	if err != nil {
		_ = s.auditStore.Append(audit.Event{
			Time:    time.Now().UTC(),
			Actor:   "ops-api",
			Action:  "prometheus_signal_eval",
			Project: project,
			Env:     envName,
			Status:  "failed",
			Message: err.Error(),
		})
	}
	report := incident.BuildReportWithContext("ops-api", envName, env, results, policyCfg, recentAutoActions, incident.ReportContext{
		RecentChanges: recentChanges,
		MetricSignals: metricSignals,
	})
	record, err := s.syncIncident(report)
	if err != nil {
		_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "incident_sync", Project: project, Env: envName, Status: "failed", Message: err.Error()})
	} else {
		_ = s.auditStore.Append(audit.Event{
			Time:    time.Now().UTC(),
			Actor:   "ops-api",
			Action:  "incident_sync",
			Project: project,
			Env:     envName,
			Target:  record.ID,
			Status:  defaultString(record.Status, "ok"),
			Message: "transition=" + incident.LifecycleTransition(record) + " summary=" + trimAuditMessage(report.Summary, 160),
		})
	}
	if s.notifyCtl.Enabled() && truthy(r.URL.Query().Get("notify")) {
		if shouldSuppressAcknowledged(record, report) {
			_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "notify", Project: project, Env: envName, Status: "suppressed", Message: "incident acknowledged by " + record.AcknowledgedBy})
		} else {
			decision, err := s.notifyCtl.Process(r.Context(), report)
			if err != nil {
				_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "notify", Project: project, Env: envName, Status: "failed", Message: err.Error()})
			} else if decision.Send {
				_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "notify", Project: project, Env: envName, Status: "ok", Message: notify.DescribeDecision(decision)})
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"project":           project,
		"env":               envName,
		"status":            report.Status,
		"results":           results,
		"recent_changes":    report.RecentChanges,
		"metric_signals":    report.MetricSignals,
		"suppressed_checks": report.SuppressedChecks,
		"suggestions":       report.Suggestions,
		"summary":           report.Summary,
		"highlights":        report.Highlights,
	})
}

func resultStatus(r checks.Result) string {
	switch r.Severity {
	case checks.SeverityWarn:
		return "warn"
	case checks.SeverityFail:
		return "fail"
	default:
		return "pass"
	}
}

func (s *server) handleRunAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req actionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.validateActionRequest(req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.Actor == "" {
		req.Actor = "ops-api"
	}
	if req.Env == "" {
		req.Env = "test"
	}
	project, err := s.projectForEnv(req.Env)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	req.TargetHost = strings.TrimSpace(req.TargetHost)
	targetHost, err := s.resolveTargetHost(req.Env, req.TargetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	cfg, err := policy.Load(s.policyFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	recentAutoActions, err := s.auditStore.CountRecentAutoActions(project, req.Env, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	decision := cfg.Evaluate(req.Action, req.Env, recentAutoActions)
	if !decision.Allowed {
		_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Project: project, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: "denied", Message: decision.Reason})
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "denied", Message: decision.Reason})
		return
	}
	if decision.RequiresApproval && !req.Approved {
		_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Project: project, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: "approval_required", Message: decision.Reason, RequiresOK: true})
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "approval_required", Message: decision.Reason + " (use /actions/request + /actions/approve)"})
		return
	}

	res := runAction(req.Action, req.Args, req.TimeoutS, targetHost)
	s.actionRecord(req.Action, res.Err == nil)
	status := "ok"
	message := "action executed"
	if res.Err != nil {
		status = "failed"
		message = res.Err.Error()
	}
	_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Project: project, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: status, Message: strings.TrimSpace(res.Output), RequiresOK: decision.RequiresApproval})

	if res.Err != nil {
		w.WriteHeader(http.StatusBadGateway)
	}
	_ = json.NewEncoder(w).Encode(actionResponse{Status: status, Message: message, ExitCode: res.ExitCode, Output: res.Output})
}

func (s *server) handleRequestAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req actionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.validateActionRequest(req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.Actor == "" {
		req.Actor = "ops-api"
	}
	if req.Env == "" {
		req.Env = "test"
	}
	project, err := s.projectForEnv(req.Env)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	req.TargetHost = strings.TrimSpace(req.TargetHost)
	targetHost, err := s.resolveTargetHost(req.Env, req.TargetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	cfg, err := policy.Load(s.policyFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	recentAutoActions, err := s.auditStore.CountRecentAutoActions(project, req.Env, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	decision := cfg.Evaluate(req.Action, req.Env, recentAutoActions)
	if !decision.Allowed {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(requestActionResponse{Status: "denied", Message: decision.Reason})
		return
	}

	rid := newID()
	now := time.Now().UTC()
	entry := approval.Request{ID: rid, Action: req.Action, Project: project, Env: req.Env, TargetHost: req.TargetHost, Args: req.Args, Actor: req.Actor, RequiresApproval: decision.RequiresApproval, Status: "pending", CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	err = s.approvalStore.Create(entry)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = s.auditStore.Append(audit.Event{Time: now, Actor: req.Actor, Action: req.Action, Project: project, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: "pending", Message: "action request created", RequiresOK: decision.RequiresApproval})

	if !decision.RequiresApproval {
		res := runAction(req.Action, req.Args, req.TimeoutS, targetHost)
		s.actionRecord(req.Action, res.Err == nil)
		newStatus := "executed"
		result := strings.TrimSpace(res.Output)
		if res.Err != nil {
			newStatus = "failed"
			if result == "" {
				result = res.Err.Error()
			}
		}
		s.mu.Lock()
		_, _ = s.approvalStore.Update(rid, func(r *approval.Request) error {
			r.Status = newStatus
			r.Result = result
			return nil
		})
		s.mu.Unlock()
		_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Project: project, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: newStatus, Message: result})
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(requestActionResponse{Status: newStatus, Message: result, RequestID: rid})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(requestActionResponse{Status: "pending", Message: "awaiting approval", RequestID: rid})
}

func (s *server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.RequestID) == "" {
		http.Error(w, `{"error":"request_id required"}`, http.StatusBadRequest)
		return
	}
	if req.Approver == "" {
		req.Approver = "ops-approver"
	}

	s.mu.Lock()
	entry, err := s.approvalStore.Update(req.RequestID, func(r *approval.Request) error {
		if r.Status != "pending" {
			return fmt.Errorf("request is not pending")
		}
		r.Status = "approved"
		r.Approver = req.Approver
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	targetHost, err := s.resolveTargetHost(entry.Env, entry.TargetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	res := runAction(entry.Action, entry.Args, req.TimeoutS, targetHost)
	s.actionRecord(entry.Action, res.Err == nil)
	finalStatus := "executed"
	result := strings.TrimSpace(res.Output)
	if res.Err != nil {
		finalStatus = "failed"
		if result == "" {
			result = res.Err.Error()
		}
	}

	s.mu.Lock()
	_, _ = s.approvalStore.Update(entry.ID, func(r *approval.Request) error {
		r.Status = finalStatus
		r.Result = result
		r.Approver = req.Approver
		return nil
	})
	s.mu.Unlock()

	_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Approver, Action: entry.Action, Project: entry.Project, Env: entry.Env, TargetHost: entry.TargetHost, Target: entry.TargetHost, Status: finalStatus, Message: result, RequiresOK: entry.RequiresApproval})
	if res.Err != nil {
		w.WriteHeader(http.StatusBadGateway)
	}
	_ = json.NewEncoder(w).Encode(actionResponse{Status: finalStatus, Message: "approval processed", ExitCode: res.ExitCode, Output: res.Output})
}

func (s *server) handleRejectAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req rejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.RequestID) == "" {
		http.Error(w, `{"error":"request_id required"}`, http.StatusBadRequest)
		return
	}
	if req.Approver == "" {
		req.Approver = "ops-approver"
	}
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "rejected by approver"
	}

	s.mu.Lock()
	entry, err := s.approvalStore.Update(req.RequestID, func(r *approval.Request) error {
		if r.Status != "pending" {
			return fmt.Errorf("request is not pending")
		}
		r.Status = "denied"
		r.Approver = req.Approver
		r.Result = req.Reason
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Approver, Action: entry.Action, Project: entry.Project, Env: entry.Env, TargetHost: entry.TargetHost, Target: entry.TargetHost, Status: "denied", Message: req.Reason, RequiresOK: entry.RequiresApproval})
	_ = json.NewEncoder(w).Encode(actionResponse{Status: "denied", Message: "request rejected"})
}

func (s *server) handlePendingActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	projects := queryProjects(r)
	s.mu.Lock()
	items, err := s.approvalStore.ListPending(limit, projects)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"count": len(items), "items": items, "projects": projects})
}

func (s *server) handleGetAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	item, err := s.approvalStore.GetByID(id)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(item)
}

func (s *server) handleListActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status == "" {
		status = "pending"
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	projects := queryProjects(r)

	s.mu.Lock()
	items, err := s.approvalStore.ListByStatus(status, 500, projects)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	start := 0
	if cursor != "" {
		for i, it := range items {
			if actionCursor(it) == cursor {
				start = i + 1
				break
			}
		}
	}
	if start > len(items) {
		start = len(items)
	}
	paged := items[start:]
	if len(paged) > limit {
		paged = paged[:limit]
	}
	nextCursor := ""
	if start+len(paged) < len(items) && len(paged) > 0 {
		nextCursor = actionCursor(paged[len(paged)-1])
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "count": len(paged), "items": paged, "next_cursor": nextCursor, "projects": projects})
}

func (s *server) handleTailAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	file := r.URL.Query().Get("file")
	resolvedFile, err := s.resolveAuditFile(file)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	projects := queryProjects(r)
	envName := strings.TrimSpace(r.URL.Query().Get("env"))
	if s.auditStore.Driver() == "sqlite" {
		events, err := s.auditStore.List(audit.Query{Projects: projects, Env: envName, Limit: limit})
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"driver": s.auditStore.Driver(), "file": resolvedFile, "count": len(events), "events": events})
		return
	}
	lines, err := tailLines(resolvedFile, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"driver": s.auditStore.Driver(), "file": resolvedFile, "count": len(lines), "lines": lines})
}

func (s *server) handleAlertmanagerWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	var payload alerting.AlertmanagerWebhook
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if len(payload.Alerts) == 0 {
		http.Error(w, `{"error":"alerts required"}`, http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	items := make([]incident.Record, 0, len(payload.Alerts))
	for _, report := range payload.Reports(now, s.projectForAlertEnv) {
		record, err := s.syncIncident(report)
		if err != nil {
			_ = s.auditStore.Append(audit.Event{
				Time:    now,
				Actor:   "alertmanager",
				Action:  "alertmanager_receive",
				Project: report.Project,
				Env:     report.Env,
				Target:  report.Source + "|" + report.Key,
				Status:  "failed",
				Message: err.Error(),
			})
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		items = append(items, record)
		_ = s.auditStore.Append(audit.Event{
			Time:    now,
			Actor:   "ops-api",
			Action:  "incident_sync",
			Project: report.Project,
			Env:     report.Env,
			Target:  record.ID,
			Status:  defaultString(record.Status, "ok"),
			Message: "transition=" + incident.LifecycleTransition(record) + " summary=" + trimAuditMessage(report.Summary, 160),
		})
		_ = s.auditStore.Append(audit.Event{
			Time:    now,
			Actor:   "alertmanager",
			Action:  "alertmanager_receive",
			Project: report.Project,
			Env:     report.Env,
			Target:  record.ID,
			Status:  report.Status,
			Message: report.Summary,
		})
	}
	_ = json.NewEncoder(w).Encode(alertmanagerIngestResponse{
		Status: "ok",
		Count:  len(items),
		Items:  items,
	})
}

func (s *server) handleIncidentSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	window := 60
	if v := r.URL.Query().Get("minutes"); v != "" {
		fmt.Sscanf(v, "%d", &window)
		if window <= 0 || window > 24*60 {
			window = 60
		}
	}
	projects := queryProjects(r)
	cutoff := time.Now().UTC().Add(-time.Duration(window) * time.Minute)
	events, err := s.auditStore.List(audit.Query{
		Since:    cutoff,
		Projects: projects,
		Limit:    5000,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	byStatus := map[string]int{}
	targetCount := map[string]int{}
	total := 0
	for _, e := range events {
		total++
		byStatus[e.Status]++
		if strings.TrimSpace(e.Target) != "" {
			targetCount[e.Target]++
		}
	}
	topTargets := topN(targetCount, 5)
	_ = json.NewEncoder(w).Encode(incidentSummary{WindowMinutes: window, Projects: projects, Total: total, ByStatus: byStatus, TopTargets: topTargets})
}

func (s *server) handlePrometheusQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	envName := strings.TrimSpace(r.URL.Query().Get("env"))
	if envName == "" {
		http.Error(w, `{"error":"env required"}`, http.StatusBadRequest)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if query == "" {
		http.Error(w, `{"error":"query required"}`, http.StatusBadRequest)
		return
	}
	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	env, ok := cfg.Environment(envName)
	if !ok {
		http.Error(w, `{"error":"env not found"}`, http.StatusNotFound)
		return
	}
	client, timeout, err := prometheusClientForEnv(env)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	window := 0
	if v := strings.TrimSpace(r.URL.Query().Get("minutes")); v != "" {
		fmt.Sscanf(v, "%d", &window)
		if window < 0 || window > 7*24*60 {
			http.Error(w, `{"error":"minutes must be between 0 and 10080"}`, http.StatusBadRequest)
			return
		}
	}
	var out promapi.QueryResponse
	if window > 0 {
		step := promapi.AutoStep(time.Duration(window) * time.Minute)
		if raw := strings.TrimSpace(r.URL.Query().Get("step")); raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed <= 0 {
				http.Error(w, `{"error":"invalid step duration"}`, http.StatusBadRequest)
				return
			}
			step = parsed
		}
		end := time.Now().UTC()
		start := end.Add(-time.Duration(window) * time.Minute)
		out, err = client.QueryRange(ctx, query, start, end, step)
	} else {
		out, err = client.QueryInstant(ctx, query, time.Now().UTC())
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"project": env.ProjectName(),
		"env":     envName,
		"data":    out,
	})
}

func (s *server) handleChangeEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req changeEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	evt, err := s.buildChangeAuditEvent(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.auditStore.Append(evt); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(evt)
}

func (s *server) handleGitHubChangeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var payload githubChangeWebhook
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	req, err := githubWebhookToChangeRequest(r, payload)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	evt, err := s.buildChangeAuditEvent(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.auditStore.Append(evt); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(evt)
}

func (s *server) handleGitLabChangeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var payload gitlabChangeWebhook
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	req, err := gitlabWebhookToChangeRequest(r, payload)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	evt, err := s.buildChangeAuditEvent(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.auditStore.Append(evt); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(evt)
}

func (s *server) handleRecentChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	window := 120
	if v := strings.TrimSpace(r.URL.Query().Get("minutes")); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &window); err != nil || window <= 0 {
			http.Error(w, `{"error":"invalid minutes"}`, http.StatusBadRequest)
			return
		}
	}
	limit := 20
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &limit); err != nil || limit <= 0 || limit > 200 {
			http.Error(w, `{"error":"invalid limit"}`, http.StatusBadRequest)
			return
		}
	}
	projects := queryProjects(r)
	envName := strings.TrimSpace(r.URL.Query().Get("env"))
	events, err := s.auditStore.List(audit.Query{
		Since:    time.Now().UTC().Add(-time.Duration(window) * time.Minute),
		Projects: projects,
		Env:      envName,
		Limit:    maxInt(limit*10, 200),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	items := make([]incident.TimelineEntry, 0, limit)
	for _, evt := range events {
		if incident.EventKind(evt) != "change" {
			continue
		}
		items = append(items, incident.TimelineEntry{
			Time:       evt.Time,
			Kind:       "change",
			Action:     strings.TrimSpace(evt.Action),
			Status:     strings.TrimSpace(evt.Status),
			Actor:      strings.TrimSpace(evt.Actor),
			Target:     strings.TrimSpace(evt.Target),
			TargetHost: strings.TrimSpace(evt.TargetHost),
			Reference:  strings.TrimSpace(evt.Reference),
			Revision:   strings.TrimSpace(evt.Revision),
			URL:        strings.TrimSpace(evt.URL),
			Message:    strings.TrimSpace(evt.Message),
		})
		if len(items) >= limit {
			break
		}
	}
	_ = json.NewEncoder(w).Encode(changesResponse{
		WindowMinutes: window,
		Projects:      projects,
		Env:           envName,
		Count:         len(items),
		Items:         items,
	})
}

func (s *server) buildChangeAuditEvent(req changeEventRequest) (audit.Event, error) {
	envName := strings.TrimSpace(req.Env)
	if envName == "" {
		return audit.Event{}, fmt.Errorf("env required")
	}
	project := strings.TrimSpace(req.Project)
	if project == "" {
		if inferred, err := s.projectForEnv(envName); err == nil {
			project = inferred
		}
	}
	if project == "" {
		project = "default"
	}
	action := normalizeChangeAction(req.Kind, req.Action)
	status := normalizeChangeStatus(req.Status)
	message := strings.TrimSpace(req.Message)
	if message == "" {
		return audit.Event{}, fmt.Errorf("message required")
	}
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		actor = "external-change"
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = envName
	}
	if len(target) > 200 || strings.Contains(target, "\n") {
		return audit.Event{}, fmt.Errorf("invalid target")
	}
	targetHost := strings.TrimSpace(req.TargetHost)
	if len(targetHost) > 200 || strings.Contains(targetHost, "\n") {
		return audit.Event{}, fmt.Errorf("invalid target_host")
	}
	if len(actor) > 200 || strings.Contains(actor, "\n") {
		return audit.Event{}, fmt.Errorf("invalid actor")
	}
	occurredAt := req.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return audit.Event{
		Time:       occurredAt,
		Actor:      actor,
		Action:     action,
		Project:    project,
		Env:        envName,
		TargetHost: targetHost,
		Target:     target,
		Reference:  normalizeChangeReference(req.Reference),
		Revision:   shortRevision(req.Revision),
		URL:        strings.TrimSpace(req.URL),
		Status:     status,
		Message:    message,
	}, nil
}

func githubWebhookToChangeRequest(r *http.Request, payload githubChangeWebhook) (changeEventRequest, error) {
	eventType := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	envName := firstNonEmptyString(
		strings.TrimSpace(r.URL.Query().Get("env")),
		githubEnvFromPayload(payload),
	)
	if envName == "" {
		return changeEventRequest{}, fmt.Errorf("env required; use deployment environment or pass ?env=<name>")
	}
	project := firstNonEmptyString(
		strings.TrimSpace(r.URL.Query().Get("project")),
	)
	kind := firstNonEmptyString(strings.TrimSpace(r.URL.Query().Get("kind")), githubKindForEvent(eventType))
	action := firstNonEmptyString(strings.TrimSpace(r.URL.Query().Get("action")), githubActionForEvent(eventType))
	actor := firstNonEmptyString(payload.Sender.Login, "github:"+firstNonEmptyString(payload.Repository.FullName, payload.Repository.Name, "unknown"))
	target := firstNonEmptyString(payload.Repository.FullName, payload.Repository.Name, envName)
	reference, revision, link, occurredAt, message := githubEventDetails(eventType, payload)
	return changeEventRequest{
		OccurredAt: occurredAt,
		Kind:       kind,
		Action:     action,
		Actor:      actor,
		Project:    project,
		Env:        envName,
		Target:     target,
		Status:     githubStatusForEvent(eventType, payload),
		Message:    message,
		Reference:  reference,
		Revision:   revision,
		URL:        link,
	}, nil
}

func gitlabWebhookToChangeRequest(r *http.Request, payload gitlabChangeWebhook) (changeEventRequest, error) {
	eventType := firstNonEmptyString(strings.TrimSpace(r.Header.Get("X-Gitlab-Event")), payload.EventName, payload.ObjectKind)
	envName := firstNonEmptyString(
		strings.TrimSpace(r.URL.Query().Get("env")),
		gitlabEnvFromPayload(payload),
	)
	if envName == "" {
		return changeEventRequest{}, fmt.Errorf("env required; provide ?env=<name> or include OPS_AGENT_ENV/CI_ENVIRONMENT_NAME in the payload")
	}
	project := firstNonEmptyString(
		strings.TrimSpace(r.URL.Query().Get("project")),
	)
	kind := firstNonEmptyString(strings.TrimSpace(r.URL.Query().Get("kind")), gitlabKindForEvent(eventType, payload))
	action := firstNonEmptyString(strings.TrimSpace(r.URL.Query().Get("action")), gitlabActionForEvent(eventType, payload))
	actor := firstNonEmptyString(payload.UserName, "gitlab:"+firstNonEmptyString(payload.Project.PathWithNamespace, payload.Project.Name, "unknown"))
	target := firstNonEmptyString(payload.Project.PathWithNamespace, payload.Project.Name, envName)
	reference, revision, link, occurredAt, message := gitlabEventDetails(eventType, payload)
	return changeEventRequest{
		OccurredAt: occurredAt,
		Kind:       kind,
		Action:     action,
		Actor:      actor,
		Project:    project,
		Env:        envName,
		Target:     target,
		Status:     gitlabStatusForEvent(eventType, payload),
		Message:    message,
		Reference:  reference,
		Revision:   revision,
		URL:        link,
	}, nil
}

func normalizeChangeAction(kind, action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "" {
		return sanitizeChangeToken(action, "change_event")
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "deploy", "release", "rollback", "maintenance", "config", "change":
		return kind + "_event"
	default:
		return "change_event"
	}
}

func sanitizeChangeToken(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToLower(strings.TrimSpace(v)) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return fallback
	}
	return out
}

func normalizeChangeStatus(v string) string {
	status := strings.ToLower(strings.TrimSpace(v))
	if status == "" {
		return "ok"
	}
	switch status {
	case "planned", "started", "ok", "failed", "rolled_back", "canceled":
		return status
	default:
		return sanitizeChangeToken(status, "ok")
	}
}

func githubEnvFromPayload(payload githubChangeWebhook) string {
	if payload.Deployment != nil {
		if env := strings.TrimSpace(payload.Deployment.Environment); env != "" {
			return env
		}
		if raw, ok := payload.Deployment.Payload["environment"]; ok {
			return strings.TrimSpace(fmt.Sprint(raw))
		}
	}
	return ""
}

func githubKindForEvent(eventType string) string {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "deployment", "deployment_status":
		return "deploy"
	case "workflow_run":
		return "change"
	default:
		return "change"
	}
}

func githubActionForEvent(eventType string) string {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "deployment", "deployment_status":
		return "deploy_event"
	case "workflow_run":
		return "change_event"
	default:
		return "change_event"
	}
}

func githubStatusForEvent(eventType string, payload githubChangeWebhook) string {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "deployment":
		return "planned"
	case "deployment_status":
		if payload.DeploymentStatus == nil {
			return "ok"
		}
		switch strings.ToLower(strings.TrimSpace(payload.DeploymentStatus.State)) {
		case "success":
			return "ok"
		case "failure", "error":
			return "failed"
		case "inactive":
			return "rolled_back"
		case "pending", "queued", "in_progress":
			return "started"
		default:
			return normalizeChangeStatus(payload.DeploymentStatus.State)
		}
	case "workflow_run":
		if payload.WorkflowRun == nil {
			return "ok"
		}
		if conclusion := strings.ToLower(strings.TrimSpace(payload.WorkflowRun.Conclusion)); conclusion != "" {
			switch conclusion {
			case "success":
				return "ok"
			case "failure", "timed_out", "action_required":
				return "failed"
			case "cancelled", "skipped", "neutral":
				return "canceled"
			default:
				return normalizeChangeStatus(conclusion)
			}
		}
		if status := strings.ToLower(strings.TrimSpace(payload.WorkflowRun.Status)); status != "" {
			switch status {
			case "completed":
				return "ok"
			case "queued", "requested", "in_progress", "waiting":
				return "started"
			default:
				return normalizeChangeStatus(status)
			}
		}
	}
	return "ok"
}

func githubEventDetails(eventType string, payload githubChangeWebhook) (reference, revision, link string, occurredAt time.Time, message string) {
	repo := firstNonEmptyString(payload.Repository.FullName, payload.Repository.Name, "unknown repo")
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "deployment":
		if payload.Deployment != nil {
			reference = normalizeChangeReference(payload.Deployment.Ref)
			revision = shortRevision(payload.Deployment.SHA)
			occurredAt = time.Now().UTC()
			message = firstNonEmptyString(payload.Deployment.Description, fmt.Sprintf("github deployment created repo=%s env=%s task=%s", repo, defaultString(payload.Deployment.Environment, "unknown"), defaultString(payload.Deployment.Task, "deploy")))
		}
	case "deployment_status":
		if payload.DeploymentStatus != nil {
			reference = normalizeChangeReference(payload.Deployment.Ref)
			revision = shortRevision(payload.Deployment.SHA)
			link = firstNonEmptyString(payload.DeploymentStatus.EnvironmentURL, payload.DeploymentStatus.LogURL, payload.DeploymentStatus.TargetURL, payload.Repository.HTMLURL)
			occurredAt = firstNonZeroTime(payload.DeploymentStatus.UpdatedAt, payload.DeploymentStatus.CreatedAt)
			message = firstNonEmptyString(payload.DeploymentStatus.Description, fmt.Sprintf("github deployment %s repo=%s env=%s", defaultString(payload.DeploymentStatus.State, "unknown"), repo, defaultString(githubEnvFromPayload(payload), "unknown")))
		}
	case "workflow_run":
		if payload.WorkflowRun != nil {
			reference = normalizeChangeReference(payload.WorkflowRun.HeadBranch)
			revision = shortRevision(payload.WorkflowRun.HeadSHA)
			link = firstNonEmptyString(payload.WorkflowRun.HTMLURL, payload.Repository.HTMLURL)
			occurredAt = firstNonZeroTime(payload.WorkflowRun.UpdatedAt, payload.WorkflowRun.CreatedAt)
			name := firstNonEmptyString(payload.WorkflowRun.Name, func() string {
				if payload.Workflow != nil {
					return payload.Workflow.Name
				}
				return ""
			}())
			message = fmt.Sprintf("github workflow %s status=%s conclusion=%s repo=%s branch=%s", defaultString(name, "workflow"), defaultString(payload.WorkflowRun.Status, "unknown"), defaultString(payload.WorkflowRun.Conclusion, "none"), repo, defaultString(payload.WorkflowRun.HeadBranch, "unknown"))
		}
	}
	if message == "" {
		message = fmt.Sprintf("github change event %s for %s", defaultString(eventType, "unknown"), repo)
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return reference, revision, link, occurredAt, message
}

func gitlabEnvFromPayload(payload gitlabChangeWebhook) string {
	for _, v := range payload.ObjectAttributes.Variables {
		key := strings.ToUpper(strings.TrimSpace(v.Key))
		switch key {
		case "OPS_AGENT_ENV", "CI_ENVIRONMENT_NAME", "DEPLOY_ENV", "ENVIRONMENT":
			if value := strings.TrimSpace(v.Value); value != "" {
				return value
			}
		}
	}
	return ""
}

func gitlabKindForEvent(eventType string, payload gitlabChangeWebhook) string {
	switch strings.ToLower(strings.TrimSpace(firstNonEmptyString(payload.ObjectKind, eventType))) {
	case "pipeline":
		if gitlabEnvFromPayload(payload) != "" {
			return "deploy"
		}
		return "change"
	case "release":
		return "release"
	default:
		return "change"
	}
}

func gitlabActionForEvent(eventType string, payload gitlabChangeWebhook) string {
	switch gitlabKindForEvent(eventType, payload) {
	case "deploy":
		return "deploy_event"
	case "release":
		return "release_event"
	default:
		return "change_event"
	}
}

func gitlabStatusForEvent(eventType string, payload gitlabChangeWebhook) string {
	switch strings.ToLower(strings.TrimSpace(firstNonEmptyString(payload.ObjectKind, eventType))) {
	case "pipeline":
		return normalizeGitlabPipelineStatus(payload.ObjectAttributes.Status, payload.ObjectAttributes.DetailedStatus)
	case "release":
		if strings.EqualFold(strings.TrimSpace(payload.Release.Action), "create") {
			return "ok"
		}
		return normalizeChangeStatus(payload.Release.Action)
	default:
		return "ok"
	}
}

func normalizeGitlabPipelineStatus(status, detailed string) string {
	status = strings.ToLower(strings.TrimSpace(firstNonEmptyString(status, detailed)))
	switch status {
	case "success":
		return "ok"
	case "failed":
		return "failed"
	case "canceled", "cancelled", "skipped":
		return "canceled"
	case "running", "pending", "preparing", "waiting_for_resource", "created", "manual":
		return "started"
	default:
		return normalizeChangeStatus(status)
	}
}

func gitlabEventDetails(eventType string, payload gitlabChangeWebhook) (reference, revision, link string, occurredAt time.Time, message string) {
	project := firstNonEmptyString(payload.Project.PathWithNamespace, payload.Project.Name, "unknown project")
	switch strings.ToLower(strings.TrimSpace(firstNonEmptyString(payload.ObjectKind, eventType))) {
	case "pipeline":
		reference = normalizeChangeReference(payload.ObjectAttributes.Ref)
		revision = shortRevision(firstNonEmptyString(payload.ObjectAttributes.SHA, payload.CheckoutSHA, payload.After))
		link = firstNonEmptyString(payload.ObjectAttributes.URL, payload.Project.WebURL)
		occurredAt = firstNonZeroTime(parseTimestamp(payload.ObjectAttributes.FinishedAt), parseTimestamp(payload.ObjectAttributes.CreatedAt))
		message = fmt.Sprintf("gitlab pipeline %s project=%s ref=%s source=%s", defaultString(payload.ObjectAttributes.Status, "unknown"), project, defaultString(payload.ObjectAttributes.Ref, "unknown"), defaultString(payload.ObjectAttributes.Source, "unknown"))
	case "release":
		reference = normalizeChangeReference(firstNonEmptyString(payload.Release.Tag, payload.Ref))
		revision = shortRevision(firstNonEmptyString(payload.CheckoutSHA, payload.After))
		link = payload.Project.WebURL
		occurredAt = payload.Release.ReleasedAt
		message = fmt.Sprintf("gitlab release %s project=%s tag=%s", defaultString(payload.Release.Action, "published"), project, defaultString(payload.Release.Tag, "unknown"))
	default:
		reference = normalizeChangeReference(payload.Ref)
		revision = shortRevision(firstNonEmptyString(payload.CheckoutSHA, payload.After))
		link = payload.Project.WebURL
		message = fmt.Sprintf("gitlab change event %s project=%s", defaultString(eventType, "unknown"), project)
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return reference, revision, link, occurredAt, message
}

func normalizeChangeReference(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	for _, prefix := range []string{"refs/heads/", "refs/tags/", "refs/remotes/origin/"} {
		if strings.HasPrefix(v, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(v, prefix))
		}
	}
	return v
}

func shortRevision(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 12 && isHexLike(v) {
		return v[:12]
	}
	return v
}

func isHexLike(v string) bool {
	if len(v) < 7 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func parseTimestamp(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339, v); err == nil {
		return parsed.UTC()
	}
	if parsed, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return parsed.UTC()
	}
	return time.Time{}
}

func firstNonZeroTime(items ...time.Time) time.Time {
	for _, item := range items {
		if !item.IsZero() {
			return item.UTC()
		}
	}
	return time.Time{}
}

func firstNonEmptyString(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func (s *server) handleIncidentStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	filter := incident.Filter{
		Projects: queryProjects(r),
		Env:      strings.TrimSpace(r.URL.Query().Get("env")),
		Source:   strings.TrimSpace(r.URL.Query().Get("source")),
	}
	items, err := s.incidentStore.List(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	_ = json.NewEncoder(w).Encode(incidentStatsResponse{
		Projects: filter.Projects,
		Env:      filter.Env,
		Source:   filter.Source,
		Summary:  incident.ComputeStats(items, now),
		Scopes:   incident.GroupStats(items, now),
	})
}

func (s *server) handleActiveIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	items, err := s.incidentStore.List(incident.Filter{
		Projects: queryProjects(r),
		Env:      strings.TrimSpace(r.URL.Query().Get("env")),
		Source:   strings.TrimSpace(r.URL.Query().Get("source")),
		OpenOnly: true,
		Limit:    limit,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"count": len(items), "items": items})
}

func (s *server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	item, ok, err := s.incidentStore.Get(id)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, `{"error":"incident not found"}`, http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(item)
}

func (s *server) handleIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	if s.auditStore == nil {
		http.Error(w, `{"error":"audit store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	window := 90
	if v := r.URL.Query().Get("minutes"); v != "" {
		fmt.Sscanf(v, "%d", &window)
		if window <= 0 || window > 24*60 {
			window = 90
		}
	}
	item, ok, err := s.incidentStore.Get(id)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, `{"error":"incident not found"}`, http.StatusNotFound)
		return
	}
	timeline, err := (incident.TimelineBuilder{Store: s.auditStore}).Build(item, time.Duration(window)*time.Minute)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(timeline)
}

func (s *server) handleAckIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	var req incidentActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Actor) == "" {
		req.Actor = "ops-api"
	}
	now := time.Now().UTC()
	item, err := s.incidentStore.Ack(req.ID, req.Actor, req.Note, now)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	_ = s.auditStore.Append(audit.Event{Time: now, Actor: req.Actor, Action: "incident_ack", Project: item.Project, Env: item.Env, Target: item.ID, Status: "ok", Message: defaultString(req.Note, "incident acknowledged")})
	if updated, silenceStatus, silenceErr := s.syncAlertmanagerSilence(r.Context(), item, req.Actor, req.Note, now); silenceErr != nil {
		_ = s.auditStore.Append(audit.Event{Time: now, Actor: req.Actor, Action: "alertmanager_silence", Project: item.Project, Env: item.Env, Target: item.ID, Status: "failed", Message: silenceErr.Error()})
	} else {
		item = updated
		if item.Silence != nil && strings.TrimSpace(item.Silence.ID) != "" && strings.TrimSpace(silenceStatus) != "" {
			_ = s.auditStore.Append(audit.Event{Time: now, Actor: req.Actor, Action: "alertmanager_silence", Project: item.Project, Env: item.Env, Target: item.ID, Status: silenceStatus, Message: "silence_id=" + item.Silence.ID})
		}
	}
	_ = json.NewEncoder(w).Encode(item)
}

func (s *server) handleUnsilenceIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	if s.auditStore == nil {
		http.Error(w, `{"error":"audit store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	var req incidentActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Actor) == "" {
		req.Actor = "ops-api"
	}
	now := time.Now().UTC()
	item, err := s.expireAlertmanagerSilence(r.Context(), req.ID, req.Actor, req.Note, now)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if item.Silence != nil && strings.TrimSpace(item.Silence.ID) != "" {
		_ = s.auditStore.Append(audit.Event{Time: now, Actor: req.Actor, Action: "alertmanager_unsilence", Project: item.Project, Env: item.Env, Target: item.ID, Status: "ok", Message: "silence_id=" + item.Silence.ID})
	}
	_ = json.NewEncoder(w).Encode(item)
}

func (s *server) handleReconcileAlertmanager(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	var req alertmanagerReconcileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Actor) == "" {
		req.Actor = "ops-api"
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(r.Context(), s.alertmanagerTimeout())
	defer cancel()
	resp, err := s.reconcileAlertmanagerSilences(ctx, req, now)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) handleAssignIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.incidentStore == nil {
		http.Error(w, `{"error":"incident store not configured"}`, http.StatusServiceUnavailable)
		return
	}
	var req incidentActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ID) == "" || strings.TrimSpace(req.Owner) == "" {
		http.Error(w, `{"error":"id and owner required"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Actor) == "" {
		req.Actor = "ops-api"
	}
	item, err := s.incidentStore.Assign(req.ID, req.Owner, req.Actor, req.Note, time.Now().UTC())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	_ = s.auditStore.Append(audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: "incident_assign", Project: item.Project, Env: item.Env, Target: item.ID, Status: "ok", Message: "owner=" + item.Owner})
	_ = json.NewEncoder(w).Encode(item)
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.metrics.mu.Lock()
	requestsTotal := cloneInt64Map(s.metrics.requestsTotal)
	errorsTotal := cloneInt64Map(s.metrics.errorsTotal)
	durationMsTotal := cloneFloat64Map(s.metrics.durationMsTotal)
	actionsTotal := cloneInt64Map(s.metrics.actionsTotal)
	actionsFailTotal := cloneInt64Map(s.metrics.actionsFailTotal)
	s.metrics.mu.Unlock()
	fmt.Fprintln(w, "# HELP ops_api_requests_total Total HTTP requests by path")
	fmt.Fprintln(w, "# TYPE ops_api_requests_total counter")
	for k, v := range requestsTotal {
		fmt.Fprintf(w, "ops_api_requests_total{path=%q} %d\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_errors_total Total HTTP 5xx and 4xx responses by path")
	fmt.Fprintln(w, "# TYPE ops_api_errors_total counter")
	for k, v := range errorsTotal {
		fmt.Fprintf(w, "ops_api_errors_total{path=%q} %d\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_request_duration_ms_total Total request duration in milliseconds by path")
	fmt.Fprintln(w, "# TYPE ops_api_request_duration_ms_total counter")
	for k, v := range durationMsTotal {
		fmt.Fprintf(w, "ops_api_request_duration_ms_total{path=%q} %.3f\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_actions_total Total action executions by action")
	fmt.Fprintln(w, "# TYPE ops_api_actions_total counter")
	for k, v := range actionsTotal {
		fmt.Fprintf(w, "ops_api_actions_total{action=%q} %d\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_action_failures_total Total failed action executions by action")
	fmt.Fprintln(w, "# TYPE ops_api_action_failures_total counter")
	for k, v := range actionsFailTotal {
		fmt.Fprintf(w, "ops_api_action_failures_total{action=%q} %d\n", k, v)
	}
	if s.incidentStore == nil {
		return
	}
	items, err := s.incidentStore.List(incident.Filter{})
	if err != nil {
		fmt.Fprintln(w, "# HELP ops_api_incident_stats_scrape_error Whether incident stats scraping failed")
		fmt.Fprintln(w, "# TYPE ops_api_incident_stats_scrape_error gauge")
		fmt.Fprintln(w, "ops_api_incident_stats_scrape_error 1")
		return
	}
	now := time.Now().UTC()
	summary := incident.ComputeStats(items, now)
	fmt.Fprintln(w, "# HELP ops_incident_records_total Total incident records tracked by the control plane")
	fmt.Fprintln(w, "# TYPE ops_incident_records_total gauge")
	fmt.Fprintf(w, "ops_incident_records_total %d\n", summary.TotalRecords)
	fmt.Fprintln(w, "# HELP ops_incident_open_records Total currently open incidents")
	fmt.Fprintln(w, "# TYPE ops_incident_open_records gauge")
	fmt.Fprintf(w, "ops_incident_open_records %d\n", summary.OpenRecords)
	fmt.Fprintln(w, "# HELP ops_incident_acknowledged_records Total acknowledged incidents")
	fmt.Fprintln(w, "# TYPE ops_incident_acknowledged_records gauge")
	fmt.Fprintf(w, "ops_incident_acknowledged_records %d\n", summary.AcknowledgedRecords)
	fmt.Fprintln(w, "# HELP ops_incident_silenced_records Total incidents with an active external silence")
	fmt.Fprintln(w, "# TYPE ops_incident_silenced_records gauge")
	fmt.Fprintf(w, "ops_incident_silenced_records %d\n", summary.SilencedRecords)
	fmt.Fprintln(w, "# HELP ops_incident_reopen_total Total reopen transitions stored in incident history")
	fmt.Fprintln(w, "# TYPE ops_incident_reopen_total gauge")
	fmt.Fprintf(w, "ops_incident_reopen_total %d\n", summary.ReopenCount)
	fmt.Fprintln(w, "# HELP ops_incident_resolution_total Total resolution transitions stored in incident history")
	fmt.Fprintln(w, "# TYPE ops_incident_resolution_total gauge")
	fmt.Fprintf(w, "ops_incident_resolution_total %d\n", summary.ResolutionCount)
	fmt.Fprintln(w, "# HELP ops_incident_ack_total Total acknowledgement events stored in incident history")
	fmt.Fprintln(w, "# TYPE ops_incident_ack_total gauge")
	fmt.Fprintf(w, "ops_incident_ack_total %d\n", summary.AckCount)
	fmt.Fprintln(w, "# HELP ops_incident_avg_mtta_seconds Average mean-time-to-ack across tracked incidents")
	fmt.Fprintln(w, "# TYPE ops_incident_avg_mtta_seconds gauge")
	fmt.Fprintf(w, "ops_incident_avg_mtta_seconds %.3f\n", summary.AvgMTTASeconds)
	fmt.Fprintln(w, "# HELP ops_incident_avg_mttr_seconds Average mean-time-to-resolve across tracked incidents")
	fmt.Fprintln(w, "# TYPE ops_incident_avg_mttr_seconds gauge")
	fmt.Fprintf(w, "ops_incident_avg_mttr_seconds %.3f\n", summary.AvgMTTRSeconds)
	fmt.Fprintln(w, "# HELP ops_incident_oldest_open_age_seconds Age in seconds of the oldest currently open incident")
	fmt.Fprintln(w, "# TYPE ops_incident_oldest_open_age_seconds gauge")
	fmt.Fprintf(w, "ops_incident_oldest_open_age_seconds %.3f\n", summary.OldestOpenAgeSeconds)
	fmt.Fprintln(w, "# HELP ops_incident_scope_open_records Open incidents grouped by project, env, and source")
	fmt.Fprintln(w, "# TYPE ops_incident_scope_open_records gauge")
	fmt.Fprintln(w, "# HELP ops_incident_scope_silenced_records Silenced incidents grouped by project, env, and source")
	fmt.Fprintln(w, "# TYPE ops_incident_scope_silenced_records gauge")
	fmt.Fprintln(w, "# HELP ops_incident_scope_avg_mtta_seconds Average mean-time-to-ack grouped by project, env, and source")
	fmt.Fprintln(w, "# TYPE ops_incident_scope_avg_mtta_seconds gauge")
	fmt.Fprintln(w, "# HELP ops_incident_scope_avg_mttr_seconds Average mean-time-to-resolve grouped by project, env, and source")
	fmt.Fprintln(w, "# TYPE ops_incident_scope_avg_mttr_seconds gauge")
	for _, scope := range incident.GroupStats(items, now) {
		fmt.Fprintf(w, "ops_incident_scope_open_records{project=%q,env=%q,source=%q} %d\n", scope.Project, scope.Env, scope.Source, scope.Stats.OpenRecords)
		fmt.Fprintf(w, "ops_incident_scope_silenced_records{project=%q,env=%q,source=%q} %d\n", scope.Project, scope.Env, scope.Source, scope.Stats.SilencedRecords)
		fmt.Fprintf(w, "ops_incident_scope_avg_mtta_seconds{project=%q,env=%q,source=%q} %.3f\n", scope.Project, scope.Env, scope.Source, scope.Stats.AvgMTTASeconds)
		fmt.Fprintf(w, "ops_incident_scope_avg_mttr_seconds{project=%q,env=%q,source=%q} %.3f\n", scope.Project, scope.Env, scope.Source, scope.Stats.AvgMTTRSeconds)
	}
}

func cloneInt64Map(src map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func cloneFloat64Map(src map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func (s *server) metricsRecord(path string, status int, d time.Duration) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.requestsTotal[path]++
	if status >= 400 {
		s.metrics.errorsTotal[path]++
	}
	s.metrics.durationMsTotal[path] += float64(d.Milliseconds())
}

func (s *server) actionRecord(action string, ok bool) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.actionsTotal[action]++
	if !ok {
		s.metrics.actionsFailTotal[action]++
	}
}

func (s *server) validateActionRequest(req actionRequest) error {
	if strings.TrimSpace(req.Action) == "" {
		return fmt.Errorf("action required")
	}
	if env := strings.TrimSpace(req.Env); env != "" {
		if len(env) > 80 || strings.Contains(env, "\n") {
			return fmt.Errorf("invalid env")
		}
	}
	if targetHost := strings.TrimSpace(req.TargetHost); targetHost != "" {
		if len(targetHost) > 120 || strings.Contains(targetHost, "\n") {
			return fmt.Errorf("invalid target_host")
		}
	}
	if _, ok := actions.Lookup(req.Action); !ok {
		return fmt.Errorf("unsupported action")
	}
	return actions.ValidateArgs(req.Action, req.Args)
}

func actionCursor(r approval.Request) string {
	return r.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + r.ID
}

func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func (s *server) resolveTargetHost(envName, targetHost string) (*config.Host, error) {
	targetHost = strings.TrimSpace(targetHost)
	if targetHost == "" {
		return nil, nil
	}
	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		return nil, err
	}
	env, ok := cfg.Environment(envName)
	if !ok {
		return nil, fmt.Errorf("env not found: %s", envName)
	}
	host, ok := env.HostByName(targetHost)
	if !ok {
		return nil, fmt.Errorf("target_host %q not found in env %q", targetHost, envName)
	}
	return &host, nil
}

func (s *server) projectForEnv(envName string) (string, error) {
	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		return "", err
	}
	if _, ok := cfg.Environment(envName); !ok {
		return "", fmt.Errorf("env not found: %s", envName)
	}
	return cfg.ProjectForEnv(envName), nil
}

func (s *server) projectForAlertEnv(envName string) string {
	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		return "default"
	}
	if _, ok := cfg.Environment(envName); !ok {
		return "default"
	}
	return cfg.ProjectForEnv(envName)
}

func (s *server) syncIncident(report incident.Report) (incident.Record, error) {
	if s.incidentStore == nil {
		return incident.Record{}, nil
	}
	return s.incidentStore.SyncReport(report, time.Now().UTC())
}

func shouldSuppressAcknowledged(rec incident.Record, report incident.Report) bool {
	if !incident.IsActionableStatus(report.Status) {
		return false
	}
	if !rec.Open || !rec.Acknowledged {
		return false
	}
	return strings.TrimSpace(rec.Fingerprint) == strings.TrimSpace(report.Fingerprint)
}

func (s *server) syncAlertmanagerSilence(ctx context.Context, item incident.Record, actor, note string, now time.Time) (incident.Record, string, error) {
	if !s.syncAlertAck {
		return item, "", nil
	}
	if item.External == nil || !strings.EqualFold(strings.TrimSpace(item.External.Provider), "alertmanager") {
		return item, "", nil
	}
	if incident.SilenceActive(item.Silence, now) {
		return item, "exists", nil
	}
	comment := strings.TrimSpace(note)
	if comment == "" {
		comment = "acknowledged from ops-agent by " + strings.TrimSpace(actor)
	}
	client := alerting.AlertmanagerClient{
		BaseURL:     strings.TrimSpace(item.External.ExternalURL),
		BearerToken: s.alertAPIToken,
		HTTPClient:  newAlertmanagerHTTPClient(10 * time.Second),
	}
	silenceID, err := client.CreateSilence(ctx, item.External, s.alertSilence, actor, comment)
	if err != nil {
		return item, "", err
	}
	updated, err := s.incidentStore.SetSilence(item.ID, incident.ExternalSilence{
		ID:        silenceID,
		Status:    "active",
		CreatedBy: strings.TrimSpace(actor),
		Comment:   comment,
		StartsAt:  now,
		EndsAt:    now.Add(s.alertSilence),
		UpdatedAt: now,
	}, now)
	if err != nil {
		return item, "", err
	}
	return updated, "ok", nil
}

func (s *server) expireAlertmanagerSilence(ctx context.Context, id, actor, note string, now time.Time) (incident.Record, error) {
	item, ok, err := s.incidentStore.Get(id)
	if err != nil {
		return incident.Record{}, err
	}
	if !ok {
		return incident.Record{}, fmt.Errorf("incident not found: %s", id)
	}
	if item.External == nil || !strings.EqualFold(strings.TrimSpace(item.External.Provider), "alertmanager") {
		return incident.Record{}, fmt.Errorf("incident is not backed by alertmanager: %s", id)
	}
	if item.Silence == nil || strings.TrimSpace(item.Silence.ID) == "" {
		return incident.Record{}, fmt.Errorf("incident has no alertmanager silence: %s", id)
	}
	if !incident.SilenceActive(item.Silence, now) {
		return incident.Record{}, fmt.Errorf("incident silence is not active: %s", id)
	}
	client := alerting.AlertmanagerClient{
		BaseURL:     strings.TrimSpace(item.External.ExternalURL),
		BearerToken: s.alertAPIToken,
		HTTPClient:  newAlertmanagerHTTPClient(10 * time.Second),
	}
	if err := client.ExpireSilence(ctx, item.External.ExternalURL, item.Silence.ID); err != nil {
		return incident.Record{}, err
	}
	return s.incidentStore.ExpireSilence(item.ID, actor, note, now)
}

func (s *server) runAlertmanagerReconciler() {
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.alertmanagerTimeout())
		defer cancel()
		resp, err := s.reconcileAlertmanagerSilences(ctx, alertmanagerReconcileRequest{Actor: "ops-api"}, time.Now().UTC())
		if err != nil {
			_ = s.auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-api",
				Action:  "alertmanager_reconcile_cycle",
				Status:  "failed",
				Message: err.Error(),
			})
			return
		}
		if resp.Checked == 0 || (resp.Updated == 0 && resp.Expired == 0 && resp.Failed == 0) {
			return
		}
		status := "ok"
		if resp.Failed > 0 {
			status = "warn"
		}
		_ = s.auditStore.Append(audit.Event{
			Time:    time.Now().UTC(),
			Actor:   "ops-api",
			Action:  "alertmanager_reconcile_cycle",
			Status:  status,
			Message: fmt.Sprintf("checked=%d updated=%d expired=%d skipped=%d failed=%d", resp.Checked, resp.Updated, resp.Expired, resp.Skipped, resp.Failed),
		})
	}

	run()
	ticker := time.NewTicker(s.alertRefresh)
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

func (s *server) alertmanagerTimeout() time.Duration {
	if s.alertTimeout <= 0 {
		return 15 * time.Second
	}
	return s.alertTimeout
}

func (s *server) reconcileAlertmanagerSilences(ctx context.Context, req alertmanagerReconcileRequest, now time.Time) (alertmanagerReconcileResponse, error) {
	resp := alertmanagerReconcileResponse{Status: "ok"}
	items, err := s.listAlertmanagerCandidates(req)
	if err != nil {
		return resp, err
	}
	for _, item := range items {
		resp.Checked++
		next, changed, expired, skipped, result, err := s.reconcileAlertmanagerSilenceState(ctx, item, req.Actor, now)
		if skipped {
			resp.Skipped++
			if req.ID != "" {
				resp.Items = append(resp.Items, result)
			}
			continue
		}
		if err != nil {
			resp.Failed++
			resp.Status = "warn"
			resp.Items = append(resp.Items, result)
			continue
		}
		if changed {
			resp.Updated++
			if expired {
				resp.Expired++
			}
			_ = next
			resp.Items = append(resp.Items, result)
		} else if req.ID != "" {
			resp.Items = append(resp.Items, result)
		}
	}
	return resp, nil
}

func (s *server) listAlertmanagerCandidates(req alertmanagerReconcileRequest) ([]incident.Record, error) {
	if strings.TrimSpace(req.ID) != "" {
		item, ok, err := s.incidentStore.Get(req.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("incident not found: %s", req.ID)
		}
		return []incident.Record{item}, nil
	}
	filter := incident.Filter{
		Env:    strings.TrimSpace(req.Env),
		Source: "alertmanager",
		Limit:  1000,
	}
	if project := strings.TrimSpace(req.Project); project != "" {
		filter.Projects = []string{project}
	}
	return s.incidentStore.List(filter)
}

func (s *server) reconcileAlertmanagerSilenceState(ctx context.Context, item incident.Record, actor string, now time.Time) (incident.Record, bool, bool, bool, alertmanagerReconcileItem, error) {
	result := alertmanagerReconcileItem{
		ID:             item.ID,
		Project:        item.Project,
		Env:            item.Env,
		PreviousStatus: incident.SilenceStatus(item.Silence, now),
	}
	if item.Silence != nil {
		result.SilenceID = strings.TrimSpace(item.Silence.ID)
	}
	if item.External == nil || !strings.EqualFold(strings.TrimSpace(item.External.Provider), "alertmanager") {
		result.Message = "incident is not backed by alertmanager"
		return item, false, false, true, result, nil
	}
	if item.Silence == nil || strings.TrimSpace(item.Silence.ID) == "" {
		result.Message = "incident has no stored silence to reconcile"
		return item, false, false, true, result, nil
	}
	client := alerting.AlertmanagerClient{
		BaseURL:     strings.TrimSpace(item.External.ExternalURL),
		BearerToken: s.alertAPIToken,
		HTTPClient:  newAlertmanagerHTTPClient(s.alertmanagerTimeout()),
	}
	remote, found, err := client.GetSilence(ctx, item.External.ExternalURL, item.Silence.ID)
	if err != nil {
		result.CurrentStatus = result.PreviousStatus
		result.Message = err.Error()
		return item, false, false, false, result, err
	}
	nextSilence := reconciledSilence(item.Silence, remote, found, now)
	result.SilenceID = nextSilence.ID
	result.CurrentStatus = incident.SilenceStatus(&nextSilence, now)
	if silencesEqual(item.Silence, &nextSilence) {
		result.Message = "no silence state change"
		return item, false, false, false, result, nil
	}
	updated, err := s.incidentStore.SetSilence(item.ID, nextSilence, now)
	if err != nil {
		result.Message = err.Error()
		return item, false, false, false, result, err
	}
	result.Updated = true
	result.Message = fmt.Sprintf("silence %s -> %s id=%s", defaultString(result.PreviousStatus, "none"), defaultString(result.CurrentStatus, "none"), result.SilenceID)
	status := "ok"
	if result.CurrentStatus == "expired" {
		status = "expired"
	}
	_ = s.auditStore.Append(audit.Event{
		Time:    now,
		Actor:   defaultString(actor, "ops-api"),
		Action:  "alertmanager_reconcile",
		Project: updated.Project,
		Env:     updated.Env,
		Target:  updated.ID,
		Status:  status,
		Message: result.Message,
	})
	return updated, true, result.CurrentStatus == "expired" && result.PreviousStatus != "expired", false, result, nil
}

func reconciledSilence(local *incident.ExternalSilence, remote alerting.GettableSilence, found bool, now time.Time) incident.ExternalSilence {
	if found {
		next := incident.ExternalSilence{
			ID:        strings.TrimSpace(remote.ID),
			Status:    strings.ToLower(strings.TrimSpace(remote.Status.State)),
			CreatedBy: strings.TrimSpace(remote.CreatedBy),
			Comment:   strings.TrimSpace(remote.Comment),
			StartsAt:  remote.StartsAt.UTC(),
			EndsAt:    remote.EndsAt.UTC(),
			UpdatedAt: remote.UpdatedAt.UTC(),
		}
		if next.ID == "" && local != nil {
			next.ID = strings.TrimSpace(local.ID)
		}
		if next.UpdatedAt.IsZero() {
			next.UpdatedAt = now.UTC()
		}
		if incident.SilenceStatus(&next, now) == "expired" {
			next.Status = "expired"
			if local != nil && !local.ExpiredAt.IsZero() {
				next.ExpiredAt = local.ExpiredAt.UTC()
				next.ExpiredBy = strings.TrimSpace(local.ExpiredBy)
			} else {
				next.ExpiredAt = now.UTC()
				next.ExpiredBy = "alertmanager"
			}
		}
		return next
	}
	next := incident.ExternalSilence{}
	if local != nil {
		next = *local
	}
	next.ID = strings.TrimSpace(next.ID)
	next.Status = "expired"
	if next.ExpiredAt.IsZero() {
		next.ExpiredAt = now.UTC()
	}
	if strings.TrimSpace(next.ExpiredBy) == "" {
		next.ExpiredBy = "alertmanager"
	}
	next.UpdatedAt = now.UTC()
	return next
}

func silencesEqual(a, b *incident.ExternalSilence) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return strings.TrimSpace(a.ID) == strings.TrimSpace(b.ID) &&
		strings.TrimSpace(a.Status) == strings.TrimSpace(b.Status) &&
		strings.TrimSpace(a.CreatedBy) == strings.TrimSpace(b.CreatedBy) &&
		strings.TrimSpace(a.Comment) == strings.TrimSpace(b.Comment) &&
		timesEqual(a.StartsAt, b.StartsAt) &&
		timesEqual(a.EndsAt, b.EndsAt) &&
		timesEqual(a.ExpiredAt, b.ExpiredAt) &&
		strings.TrimSpace(a.ExpiredBy) == strings.TrimSpace(b.ExpiredBy) &&
		timesEqual(a.UpdatedAt, b.UpdatedAt)
}

func timesEqual(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return a.IsZero() && b.IsZero()
	}
	return a.UTC().Equal(b.UTC())
}

func prometheusClientForEnv(env config.Environment) (promapi.Client, time.Duration, error) {
	return promapi.ClientForConfig(env.Prometheus, newPrometheusHTTPClient(env.Prometheus.WithDefaults().Timeout))
}

func evaluatePrometheusSignals(ctx context.Context, envName string, env config.Environment) ([]promapi.SignalObservation, error) {
	cfg := env.Prometheus.WithDefaults()
	if len(cfg.Signals) == 0 {
		return nil, nil
	}
	client, timeout, err := prometheusClientForEnv(env)
	if err != nil {
		return nil, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return promapi.EvaluateSignals(queryCtx, client, envName, env, time.Now().UTC())
}

func (s *server) resolveAuditFile(name string) (string, error) {
	baseDir, err := filepath.Abs(filepath.Dir(s.auditFile))
	if err != nil {
		return "", err
	}
	canonicalBaseDir, err := filepath.EvalSymlinks(baseDir)
	if err == nil {
		baseDir = canonicalBaseDir
	}
	if strings.TrimSpace(name) == "" {
		resolvedDefault, err := filepath.Abs(s.auditFile)
		if err != nil {
			return "", err
		}
		if resolvedDefault, err = filepath.EvalSymlinks(resolvedDefault); err == nil {
			return resolvedDefault, nil
		}
		return resolvedDefault, nil
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("file must be a basename within the audit directory")
	}
	allowedExt := ".jsonl"
	if s.auditStore != nil && s.auditStore.Driver() == "sqlite" {
		allowedExt = ".db"
	}
	if filepath.Ext(name) != allowedExt {
		return "", fmt.Errorf("file must end with %s", allowedExt)
	}
	candidate := filepath.Join(baseDir, name)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		if os.IsNotExist(err) {
			return "", err
		}
		resolved = candidate
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseDir, resolved)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("file escapes audit directory")
	}
	return resolved, nil
}

func queryProjects(r *http.Request) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range r.URL.Query()["project"] {
		for _, part := range strings.Split(raw, ",") {
			project := strings.TrimSpace(part)
			if project == "" {
				continue
			}
			if _, ok := seen[project]; ok {
				continue
			}
			seen[project] = struct{}{}
			out = append(out, project)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func tailLines(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines := make([]string, 0, limit)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > limit {
			lines = lines[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func topN(m map[string]int, n int) []string {
	type kv struct {
		K string
		V int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].V > arr[j].V })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, fmt.Sprintf("%s (%d)", x.K, x.V))
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func trimAuditMessage(v string, limit int) string {
	v = strings.TrimSpace(v)
	if limit <= 0 || len(v) <= limit {
		return v
	}
	if limit < 4 {
		return v[:limit]
	}
	return v[:limit-3] + "..."
}

func runAction(action string, args []string, timeoutS int, host *config.Host) rbexec.Result {
	timeout := 30 * time.Second
	if timeoutS > 0 {
		timeout = time.Duration(timeoutS) * time.Second
	}
	return rbexec.RunAction(context.Background(), action, args, timeout, rbexec.Options{Host: host})
}

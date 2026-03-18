package notify

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
	"gopkg.in/yaml.v3"
)

type DeliveryResolver interface {
	Resolve(report incident.Report, now time.Time) Delivery
}

type Delivery struct {
	Allowed   bool
	Reason    string
	Notifier  Notifier
	Receivers []string
}

type RoutingConfig struct {
	DefaultReceiver    string              `yaml:"default_receiver"`
	Receivers          map[string]Receiver `yaml:"receivers"`
	Routes             []Route             `yaml:"routes"`
	Silences           []Silence           `yaml:"silences"`
	MaintenanceWindows []MaintenanceWindow `yaml:"maintenance_windows"`
}

type Receiver struct {
	Webhook          string `yaml:"webhook"`
	SlackWebhook     string `yaml:"slack_webhook"`
	TelegramBotToken string `yaml:"telegram_bot_token"`
	TelegramChatID   string `yaml:"telegram_chat_id"`
}

type Route struct {
	Name     string   `yaml:"name"`
	Receiver string   `yaml:"receiver"`
	Continue bool     `yaml:"continue"`
	Match    Matchers `yaml:"match"`
}

type Matchers struct {
	Env      []string `yaml:"env"`
	Source   []string `yaml:"source"`
	Severity []string `yaml:"severity"`
}

type Silence struct {
	Name     string   `yaml:"name"`
	Reason   string   `yaml:"reason"`
	StartsAt string   `yaml:"starts_at"`
	EndsAt   string   `yaml:"ends_at"`
	Match    Matchers `yaml:"match"`
}

type MaintenanceWindow struct {
	Name      string          `yaml:"name"`
	Reason    string          `yaml:"reason"`
	StartsAt  string          `yaml:"starts_at"`
	EndsAt    string          `yaml:"ends_at"`
	Recurring *RecurringRange `yaml:"recurring"`
	Match     Matchers        `yaml:"match"`
}

type RecurringRange struct {
	Timezone string   `yaml:"timezone"`
	Weekdays []string `yaml:"weekdays"`
	Start    string   `yaml:"start"`
	End      string   `yaml:"end"`
}

func LoadRouting(path string) (RoutingConfig, error) {
	var cfg RoutingConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c RoutingConfig) Validate() error {
	if len(c.Receivers) == 0 {
		return fmt.Errorf("notification config must define at least one receiver")
	}
	for name, recv := range c.Receivers {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("receiver name must not be empty")
		}
		if _, err := recv.Notifier(); err != nil {
			return fmt.Errorf("receiver %q invalid: %w", name, err)
		}
	}
	if name := strings.TrimSpace(c.DefaultReceiver); name != "" {
		if _, ok := c.Receivers[name]; !ok {
			return fmt.Errorf("default receiver %q is not defined", name)
		}
	}
	if len(c.Routes) == 0 && strings.TrimSpace(c.DefaultReceiver) == "" {
		return fmt.Errorf("notification config must define at least one route or default_receiver")
	}
	for i, route := range c.Routes {
		if strings.TrimSpace(route.Receiver) == "" {
			return fmt.Errorf("route %d must define receiver", i+1)
		}
		if _, ok := c.Receivers[route.Receiver]; !ok {
			return fmt.Errorf("route %q references undefined receiver %q", routeName(route, i), route.Receiver)
		}
		if err := route.Match.Validate(); err != nil {
			return fmt.Errorf("route %q invalid matchers: %w", routeName(route, i), err)
		}
	}
	for i, silence := range c.Silences {
		if strings.TrimSpace(silence.Name) == "" {
			return fmt.Errorf("silence %d must define name", i+1)
		}
		if err := silence.Match.Validate(); err != nil {
			return fmt.Errorf("silence %q invalid matchers: %w", silence.Name, err)
		}
		start, end, err := parseWindow(silence.StartsAt, silence.EndsAt)
		if err != nil {
			return fmt.Errorf("silence %q invalid time range: %w", silence.Name, err)
		}
		if !end.After(start) {
			return fmt.Errorf("silence %q must end after it starts", silence.Name)
		}
	}
	for i, window := range c.MaintenanceWindows {
		if strings.TrimSpace(window.Name) == "" {
			return fmt.Errorf("maintenance window %d must define name", i+1)
		}
		if err := window.Match.Validate(); err != nil {
			return fmt.Errorf("maintenance window %q invalid matchers: %w", window.Name, err)
		}
		if strings.TrimSpace(window.StartsAt) != "" || strings.TrimSpace(window.EndsAt) != "" {
			start, end, err := parseWindow(window.StartsAt, window.EndsAt)
			if err != nil {
				return fmt.Errorf("maintenance window %q invalid time range: %w", window.Name, err)
			}
			if !end.After(start) {
				return fmt.Errorf("maintenance window %q must end after it starts", window.Name)
			}
		}
		if window.Recurring != nil {
			if err := window.Recurring.Validate(); err != nil {
				return fmt.Errorf("maintenance window %q invalid recurring rule: %w", window.Name, err)
			}
		}
		if strings.TrimSpace(window.StartsAt) == "" && strings.TrimSpace(window.EndsAt) == "" && window.Recurring == nil {
			return fmt.Errorf("maintenance window %q must define starts_at/ends_at or recurring", window.Name)
		}
	}
	return nil
}

func (c RoutingConfig) BuildResolver() (DeliveryResolver, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	receivers := make(map[string]Notifier, len(c.Receivers))
	for name, recv := range c.Receivers {
		notifier, err := recv.Notifier()
		if err != nil {
			return nil, fmt.Errorf("receiver %q invalid: %w", name, err)
		}
		receivers[name] = notifier
	}
	return Router{
		DefaultReceiver:    strings.TrimSpace(c.DefaultReceiver),
		Receivers:          receivers,
		Routes:             append([]Route(nil), c.Routes...),
		Silences:           append([]Silence(nil), c.Silences...),
		MaintenanceWindows: append([]MaintenanceWindow(nil), c.MaintenanceWindows...),
	}, nil
}

func (r Receiver) Notifier() (Notifier, error) {
	notifier := Build(r.Webhook, r.SlackWebhook, r.TelegramBotToken, r.TelegramChatID)
	if notifier == nil {
		return nil, fmt.Errorf("receiver must define at least one delivery target")
	}
	return notifier, nil
}

func (m Matchers) Validate() error {
	for _, item := range m.Env {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("env matcher contains empty value")
		}
	}
	for _, item := range m.Source {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("source matcher contains empty value")
		}
	}
	for _, item := range m.Severity {
		if err := ValidateMinSeverity(item); err != nil {
			return err
		}
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("severity matcher contains empty value")
		}
	}
	return nil
}

func (m Matchers) Matches(report incident.Report) bool {
	if !matchAny(m.Env, report.Env) {
		return false
	}
	if !matchAny(m.Source, report.Source) {
		return false
	}
	if !matchAny(m.Severity, report.Status) {
		return false
	}
	return true
}

type Router struct {
	DefaultReceiver    string
	Receivers          map[string]Notifier
	Routes             []Route
	Silences           []Silence
	MaintenanceWindows []MaintenanceWindow
}

func (r Router) Resolve(report incident.Report, now time.Time) Delivery {
	for _, silence := range r.Silences {
		if silence.ActiveAt(now) && silence.Match.Matches(report) {
			return Delivery{Allowed: false, Reason: "silenced by " + silence.Name}
		}
	}
	for _, window := range r.MaintenanceWindows {
		if window.ActiveAt(now) && window.Match.Matches(report) {
			return Delivery{Allowed: false, Reason: "suppressed by maintenance window " + window.Name}
		}
	}

	var selected []Notifier
	var receiverNames []string
	seen := map[string]bool{}
	for i, route := range r.Routes {
		if !route.Match.Matches(report) {
			continue
		}
		if !seen[route.Receiver] {
			selected = append(selected, r.Receivers[route.Receiver])
			receiverNames = append(receiverNames, route.Receiver)
			seen[route.Receiver] = true
		}
		if !route.Continue {
			return Delivery{
				Allowed:   true,
				Reason:    fmt.Sprintf("routed by %s to %s", routeName(route, i), strings.Join(receiverNames, ",")),
				Notifier:  combineNotifiers(selected),
				Receivers: receiverNames,
			}
		}
	}
	if len(selected) > 0 {
		return Delivery{
			Allowed:   true,
			Reason:    "routed to " + strings.Join(receiverNames, ","),
			Notifier:  combineNotifiers(selected),
			Receivers: receiverNames,
		}
	}
	if name := strings.TrimSpace(r.DefaultReceiver); name != "" {
		return Delivery{
			Allowed:   true,
			Reason:    "routed to default receiver " + name,
			Notifier:  r.Receivers[name],
			Receivers: []string{name},
		}
	}
	return Delivery{Allowed: false, Reason: "no notification route matched"}
}

func (s Silence) ActiveAt(now time.Time) bool {
	start, end, err := parseWindow(s.StartsAt, s.EndsAt)
	if err != nil {
		return false
	}
	return !now.Before(start) && now.Before(end)
}

func (w MaintenanceWindow) ActiveAt(now time.Time) bool {
	if strings.TrimSpace(w.StartsAt) != "" || strings.TrimSpace(w.EndsAt) != "" {
		start, end, err := parseWindow(w.StartsAt, w.EndsAt)
		if err == nil && !now.Before(start) && now.Before(end) {
			return true
		}
	}
	if w.Recurring != nil {
		return w.Recurring.ActiveAt(now)
	}
	return false
}

func (r RecurringRange) Validate() error {
	if strings.TrimSpace(r.Timezone) == "" {
		return fmt.Errorf("timezone is required")
	}
	if _, err := time.LoadLocation(strings.TrimSpace(r.Timezone)); err != nil {
		return err
	}
	if len(r.Weekdays) == 0 {
		return fmt.Errorf("weekdays are required")
	}
	for _, day := range r.Weekdays {
		if _, err := parseWeekday(day); err != nil {
			return err
		}
	}
	startMin, err := parseClock(r.Start)
	if err != nil {
		return fmt.Errorf("start invalid: %w", err)
	}
	endMin, err := parseClock(r.End)
	if err != nil {
		return fmt.Errorf("end invalid: %w", err)
	}
	if startMin == endMin {
		return fmt.Errorf("start and end must not be equal")
	}
	return nil
}

func (r RecurringRange) ActiveAt(now time.Time) bool {
	loc, err := time.LoadLocation(strings.TrimSpace(r.Timezone))
	if err != nil {
		return false
	}
	startMin, err := parseClock(r.Start)
	if err != nil {
		return false
	}
	endMin, err := parseClock(r.End)
	if err != nil {
		return false
	}
	weekdaySet := map[time.Weekday]bool{}
	for _, day := range r.Weekdays {
		wd, err := parseWeekday(day)
		if err != nil {
			return false
		}
		weekdaySet[wd] = true
	}

	localNow := now.In(loc)
	minuteOfDay := localNow.Hour()*60 + localNow.Minute()
	if startMin < endMin {
		return weekdaySet[localNow.Weekday()] && minuteOfDay >= startMin && minuteOfDay < endMin
	}
	if weekdaySet[localNow.Weekday()] && minuteOfDay >= startMin {
		return true
	}
	yesterday := localNow.AddDate(0, 0, -1).Weekday()
	return weekdaySet[yesterday] && minuteOfDay < endMin
}

func combineNotifiers(items []Notifier) Notifier {
	switch len(items) {
	case 0:
		return nil
	case 1:
		return items[0]
	default:
		return Multi{Items: items}
	}
}

func parseWindow(startRaw, endRaw string) (time.Time, time.Time, error) {
	start, err := time.Parse(time.RFC3339, strings.TrimSpace(startRaw))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	end, err := time.Parse(time.RFC3339, strings.TrimSpace(endRaw))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return start.UTC(), end.UTC(), nil
}

func parseClock(v string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(v))
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

func parseWeekday(v string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	default:
		return time.Sunday, fmt.Errorf("unsupported weekday %q", v)
	}
}

func routeName(route Route, index int) string {
	if strings.TrimSpace(route.Name) != "" {
		return route.Name
	}
	return fmt.Sprintf("route#%d", index+1)
}

func matchAny(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if strings.EqualFold(strings.TrimSpace(pattern), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

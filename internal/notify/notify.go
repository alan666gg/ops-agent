package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
)

type Notifier interface {
	Notify(ctx context.Context, report incident.Report) error
}

type Multi struct {
	Items []Notifier
}

func (m Multi) Notify(ctx context.Context, report incident.Report) error {
	for _, item := range m.Items {
		if item == nil {
			continue
		}
		if err := item.Notify(ctx, report); err != nil {
			return err
		}
	}
	return nil
}

type Webhook struct {
	URL    string
	Client *http.Client
}

func (w Webhook) Notify(ctx context.Context, report incident.Report) error {
	return postJSON(ctx, clientOrDefault(w.Client), w.URL, report)
}

type Slack struct {
	WebhookURL string
	Client     *http.Client
}

func (s Slack) Notify(ctx context.Context, report incident.Report) error {
	payload := map[string]string{"text": TextMessage(report)}
	return postJSON(ctx, clientOrDefault(s.Client), s.WebhookURL, payload)
}

type Telegram struct {
	BotToken string
	ChatID   string
	Client   *http.Client
	BaseURL  string
}

func (t Telegram) Notify(ctx context.Context, report incident.Report) error {
	base := strings.TrimSpace(t.BaseURL)
	if base == "" {
		base = "https://api.telegram.org"
	}
	payload := map[string]any{
		"chat_id":                  t.ChatID,
		"text":                     TextMessage(report),
		"disable_web_page_preview": true,
	}
	return postJSON(ctx, clientOrDefault(t.Client), strings.TrimRight(base, "/")+"/bot"+t.BotToken+"/sendMessage", payload)
}

func clientOrDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func Build(webhookURL, slackWebhookURL, telegramBotToken, telegramChatID string) Notifier {
	var items []Notifier
	if strings.TrimSpace(webhookURL) != "" {
		items = append(items, Webhook{URL: strings.TrimSpace(webhookURL)})
	}
	if strings.TrimSpace(slackWebhookURL) != "" {
		items = append(items, Slack{WebhookURL: strings.TrimSpace(slackWebhookURL)})
	}
	if strings.TrimSpace(telegramBotToken) != "" && strings.TrimSpace(telegramChatID) != "" {
		items = append(items, Telegram{BotToken: strings.TrimSpace(telegramBotToken), ChatID: strings.TrimSpace(telegramChatID)})
	}
	switch len(items) {
	case 0:
		return nil
	case 1:
		return items[0]
	default:
		return Multi{Items: items}
	}
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, payload any) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("notification endpoint is empty")
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notification request failed with status %d", resp.StatusCode)
	}
	return nil
}

func TextMessage(report incident.Report) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("[%s] %s", strings.ToUpper(report.Status), report.Summary))
	for _, item := range append([]incident.Suggestion(nil), report.Suggestions...) {
		target := ""
		if item.TargetHost != "" {
			target = " target=" + item.TargetHost
		}
		approval := ""
		if item.RequiresApproval {
			approval = " approval_required"
		}
		args := ""
		if len(item.Args) > 0 {
			args = " args=" + strings.Join(item.Args, ",")
		}
		lines = append(lines, fmt.Sprintf("- suggest %s%s%s%s", item.Action, target, args, approval))
	}
	for _, res := range report.FailedChecks {
		lines = append(lines, fmt.Sprintf("- fail %s: %s", res.Name, res.Message))
	}
	for _, res := range report.WarningChecks {
		lines = append(lines, fmt.Sprintf("- warn %s: %s", res.Name, res.Message))
	}
	return strings.Join(lines, "\n")
}

func ShouldNotify(status, min string) bool {
	return severityRank(status) >= severityRankOrDefault(min, "warn")
}

func severityRank(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "fail":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

func severityRankOrDefault(v, fallback string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ok", "warn", "fail":
		return severityRank(v)
	default:
		return severityRank(fallback)
	}
}

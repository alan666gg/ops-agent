package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
)

type AlertmanagerClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
}

type SilenceRequest struct {
	StartsAt  time.Time `json:"startsAt"`
	EndsAt    time.Time `json:"endsAt"`
	CreatedBy string    `json:"createdBy"`
	Comment   string    `json:"comment"`
	Matchers  []Matcher `json:"matchers"`
}

type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
}

func (c AlertmanagerClient) CreateSilence(ctx context.Context, ref *incident.ExternalAlert, duration time.Duration, actor, comment string) (string, error) {
	if ref == nil || !strings.EqualFold(strings.TrimSpace(ref.Provider), "alertmanager") {
		return "", fmt.Errorf("incident has no alertmanager external reference")
	}
	baseURL := strings.TrimSpace(ref.ExternalURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(c.BaseURL)
	}
	if baseURL == "" {
		return "", fmt.Errorf("alertmanager external url is empty")
	}
	if duration <= 0 {
		duration = 2 * time.Hour
	}
	matchers := buildMatchers(ref)
	if len(matchers) == 0 {
		return "", fmt.Errorf("alertmanager labels are empty")
	}
	body, err := json.Marshal(SilenceRequest{
		StartsAt:  time.Now().UTC(),
		EndsAt:    time.Now().UTC().Add(duration),
		CreatedBy: defaultString(actor, "ops-agent"),
		Comment:   defaultString(comment, "silenced from ops-agent incident ack"),
		Matchers:  matchers,
	})
	if err != nil {
		return "", err
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/v2/silences", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.BearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.BearerToken))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("alertmanager silence failed: http %d", resp.StatusCode)
	}
	var out struct {
		SilenceID string `json:"silenceID"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.SilenceID) == "" {
		return "", fmt.Errorf("alertmanager silence response missing silenceID")
	}
	return strings.TrimSpace(out.SilenceID), nil
}

func (c AlertmanagerClient) ExpireSilence(ctx context.Context, baseURL, silenceID string) error {
	baseURL = strings.TrimSpace(baseURL)
	silenceID = strings.TrimSpace(silenceID)
	if baseURL == "" {
		baseURL = strings.TrimSpace(c.BaseURL)
	}
	if baseURL == "" {
		return fmt.Errorf("alertmanager external url is empty")
	}
	if silenceID == "" {
		return fmt.Errorf("alertmanager silence id is empty")
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(baseURL, "/")+"/api/v2/silence/"+silenceID, nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.BearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.BearerToken))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alertmanager expire silence failed: http %d", resp.StatusCode)
	}
	return nil
}

func buildMatchers(ref *incident.ExternalAlert) []Matcher {
	if ref == nil || len(ref.Labels) == 0 {
		return nil
	}
	matchers := make([]Matcher, 0, len(ref.Labels))
	for key, value := range ref.Labels {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		matchers = append(matchers, Matcher{Name: key, Value: value, IsRegex: false})
	}
	return matchers
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

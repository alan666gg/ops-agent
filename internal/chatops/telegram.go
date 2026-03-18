package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/approval"
)

type TelegramClient struct {
	BotToken string
	BaseURL  string
	Client   *http.Client
}

type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

type Message struct {
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
	From      User   `json:"from"`
	Chat      Chat   `json:"chat"`
}

type CallbackQuery struct {
	ID      string  `json:"id"`
	Data    string  `json:"data"`
	From    User    `json:"from"`
	Message Message `json:"message"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type sendMessageRequest struct {
	ChatID      int64  `json:"chat_id"`
	Text        string `json:"text"`
	ReplyMarkup any    `json:"reply_markup,omitempty"`
}

type replyMarkup struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard,omitempty"`
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type getUpdatesResponse struct {
	OK     bool     `json:"ok"`
	Result []Update `json:"result"`
}

type apiResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

type OffsetStore struct {
	Path string
}

func (c TelegramClient) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: timeout + 5*time.Second}
	}
	q := fmt.Sprintf("?offset=%d&timeout=%d", offset, int(timeout.Seconds()))
	var out getUpdatesResponse
	if err := c.doJSON(ctx, http.MethodGet, "/getUpdates"+q, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (c TelegramClient) SendMessage(ctx context.Context, chatID int64, text string, markup any) error {
	req := sendMessageRequest{
		ChatID:      chatID,
		Text:        trimMessage(text, 4000),
		ReplyMarkup: markup,
	}
	return c.doJSON(ctx, http.MethodPost, "/sendMessage", req, nil)
}

func (c TelegramClient) AnswerCallbackQuery(ctx context.Context, id, text string) error {
	body := map[string]any{"callback_query_id": id}
	if strings.TrimSpace(text) != "" {
		body["text"] = trimMessage(text, 180)
	}
	return c.doJSON(ctx, http.MethodPost, "/answerCallbackQuery", body, nil)
}

func (s OffsetStore) Load() (int64, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s OffsetStore) Save(offset int64) error {
	if s.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.Path, []byte(strconv.FormatInt(offset, 10)), 0o644)
}

func (c TelegramClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 20 * time.Second}
	}
	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		base = "https://api.telegram.org"
	}
	fullURL := strings.TrimRight(base, "/") + "/bot" + strings.TrimSpace(c.BotToken) + path
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram %s %s: %s", method, path, strings.TrimSpace(string(data)))
	}
	if out == nil {
		var payload apiResponse
		if err := json.Unmarshal(data, &payload); err == nil && !payload.OK && payload.Description != "" {
			return fmt.Errorf("telegram api: %s", payload.Description)
		}
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	if result, ok := out.(*getUpdatesResponse); ok && !result.OK {
		return fmt.Errorf("telegram api getUpdates failed")
	}
	return nil
}

func trimMessage(v string, limit int) string {
	v = strings.TrimSpace(v)
	if limit <= 0 || len(v) <= limit {
		return v
	}
	if limit < 4 {
		return v[:limit]
	}
	return v[:limit-3] + "..."
}

func PendingMarkup(items []approval.Request) any {
	if len(items) == 0 {
		return nil
	}
	rows := make([][]inlineButton, 0, len(items))
	for i, item := range items {
		if i >= 5 {
			break
		}
		rows = append(rows, []inlineButton{
			{Text: "View " + item.ID, CallbackData: "show:" + item.ID},
			{Text: "Approve " + item.ID, CallbackData: "approve:" + item.ID},
			{Text: "Reject " + item.ID, CallbackData: "reject:" + item.ID},
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return replyMarkup{InlineKeyboard: rows}
}

func ActionMarkup(item approval.Request) any {
	switch item.Status {
	case "pending":
		return replyMarkup{InlineKeyboard: [][]inlineButton{
			{
				{Text: "Approve " + item.ID, CallbackData: "approve:" + item.ID},
				{Text: "Reject " + item.ID, CallbackData: "reject:" + item.ID},
			},
		}}
	default:
		return nil
	}
}

func ConfirmationMarkup() any {
	return replyMarkup{InlineKeyboard: [][]inlineButton{
		{
			{Text: "Confirm", CallbackData: "llm_confirm"},
			{Text: "Cancel", CallbackData: "llm_cancel"},
		},
	}}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/chatops"
)

func main() {
	apiBase := flag.String("api-base", "http://127.0.0.1:8090", "ops-api base url")
	apiToken := flag.String("api-token", os.Getenv("OPS_API_TOKEN"), "ops-api bearer token")
	botToken := flag.String("bot-token", os.Getenv("OPS_TG_BOT_TOKEN"), "telegram bot token")
	chatID := flag.Int64("chat-id", 0, "authorized telegram chat id")
	offsetFile := flag.String("offset-file", "audit/telegram-offset.txt", "telegram long-poll offset state file")
	pollTimeout := flag.Duration("poll-timeout", 20*time.Second, "telegram getUpdates long poll timeout")
	approveTimeout := flag.Int("approve-timeout-seconds", 30, "timeout passed to /actions/approve")
	telegramBase := flag.String("telegram-base", "", "override telegram api base url")
	flag.Parse()

	if strings.TrimSpace(*botToken) == "" {
		log.Fatal("bot-token is required")
	}
	if *chatID == 0 {
		log.Fatal("chat-id is required")
	}

	apiClient := chatops.OpsAPIClient{
		BaseURL: *apiBase,
		Token:   strings.TrimSpace(*apiToken),
	}
	tg := chatops.TelegramClient{
		BotToken: strings.TrimSpace(*botToken),
		BaseURL:  strings.TrimSpace(*telegramBase),
	}
	store := chatops.OffsetStore{Path: *offsetFile}
	offset, err := store.Load()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("ops-telegram polling started api=%s chat_id=%d", *apiBase, *chatID)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), *pollTimeout+10*time.Second)
		updates, err := tg.GetUpdates(ctx, offset, *pollTimeout)
		cancel()
		if err != nil {
			log.Printf("telegram poll error: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		for _, update := range updates {
			offset = update.UpdateID + 1
			if err := store.Save(offset); err != nil {
				log.Printf("save offset error: %v", err)
			}
			if err := handleUpdate(tg, apiClient, update, *chatID, *approveTimeout); err != nil {
				log.Printf("update %d error: %v", update.UpdateID, err)
			}
		}
	}
}

func handleUpdate(tg chatops.TelegramClient, api chatops.OpsAPIClient, update chatops.Update, allowedChatID int64, approveTimeout int) error {
	switch {
	case update.Message != nil:
		msg := update.Message
		if msg.Chat.ID != allowedChatID {
			return nil
		}
		if strings.TrimSpace(msg.Text) == "" {
			return nil
		}
		reply, markup := handleCommand(context.Background(), api, msg.Text, actorForUser(msg.From), approveTimeout)
		if strings.TrimSpace(reply) == "" {
			return nil
		}
		return tg.SendMessage(context.Background(), msg.Chat.ID, reply, markup)
	case update.CallbackQuery != nil:
		cb := update.CallbackQuery
		if cb.Message.Chat.ID != allowedChatID {
			_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, "unauthorized")
			return nil
		}
		reply, err := handleCallback(context.Background(), api, cb.Data, actorForUser(cb.From), approveTimeout)
		if err != nil {
			_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, trimCallback(err.Error()))
			return tg.SendMessage(context.Background(), cb.Message.Chat.ID, "callback failed: "+err.Error(), nil)
		}
		_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, trimCallback(reply))
		return tg.SendMessage(context.Background(), cb.Message.Chat.ID, reply, nil)
	default:
		return nil
	}
}

func handleCommand(ctx context.Context, api chatops.OpsAPIClient, text, actor string, approveTimeout int) (string, any) {
	cmd, err := chatops.ParseCommand(text)
	if err != nil {
		return err.Error() + "\n\n" + chatops.HelpText(), nil
	}
	switch cmd.Name {
	case "start", "help":
		return chatops.HelpText(), nil
	case "health":
		resp, err := api.Health(ctx, cmd.Env)
		if err != nil {
			return "health failed: " + err.Error(), nil
		}
		return chatops.FormatHealth(resp), nil
	case "incidents":
		resp, err := api.IncidentSummary(ctx, cmd.Minutes)
		if err != nil {
			return "incident summary failed: " + err.Error(), nil
		}
		return chatops.FormatIncidentSummary(resp), nil
	case "pending":
		resp, err := api.Pending(ctx, 10)
		if err != nil {
			return "pending query failed: " + err.Error(), nil
		}
		return chatops.FormatPending(resp), chatops.PendingMarkup(resp.Items)
	case "approve":
		resp, err := api.Approve(ctx, cmd.RequestID, actor, approveTimeout)
		if err != nil {
			return "approve failed: " + err.Error(), nil
		}
		return fmt.Sprintf("approved %s\nstatus=%s\nmessage=%s", cmd.RequestID, resp.Status, strings.TrimSpace(resp.Message)), nil
	case "reject":
		resp, err := api.Reject(ctx, cmd.RequestID, actor, cmd.Reason)
		if err != nil {
			return "reject failed: " + err.Error(), nil
		}
		return fmt.Sprintf("rejected %s\nstatus=%s\nmessage=%s", cmd.RequestID, resp.Status, strings.TrimSpace(resp.Message)), nil
	case "request":
		resp, err := api.RequestAction(ctx, chatops.RequestActionRequest{
			Action:     cmd.Action,
			Env:        cmd.Env,
			TargetHost: cmd.TargetHost,
			Args:       cmd.Args,
			Actor:      actor,
		})
		if err != nil {
			return "request failed: " + err.Error(), nil
		}
		return fmt.Sprintf("request %s\nstatus=%s\nmessage=%s", defaultString(resp.RequestID, "(none)"), resp.Status, strings.TrimSpace(resp.Message)), nil
	default:
		return chatops.HelpText(), nil
	}
}

func handleCallback(ctx context.Context, api chatops.OpsAPIClient, data, actor string, approveTimeout int) (string, error) {
	switch {
	case strings.HasPrefix(data, "approve:"):
		id := strings.TrimPrefix(data, "approve:")
		resp, err := api.Approve(ctx, id, actor, approveTimeout)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("approved %s\nstatus=%s", id, resp.Status), nil
	case strings.HasPrefix(data, "reject:"):
		id := strings.TrimPrefix(data, "reject:")
		resp, err := api.Reject(ctx, id, actor, "rejected from telegram button")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("rejected %s\nstatus=%s", id, resp.Status), nil
	default:
		return "", fmt.Errorf("unsupported callback")
	}
}

func actorForUser(user chatops.User) string {
	if strings.TrimSpace(user.Username) != "" {
		return "tg:@" + strings.TrimSpace(user.Username)
	}
	return fmt.Sprintf("tg:%d", user.ID)
}

func trimCallback(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 180 {
		return v
	}
	return v[:177] + "..."
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

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
	auditFile := flag.String("audit", "audit/telegram.jsonl", "audit output jsonl for telegram chatops and llm actions")
	openAIAPIKey := flag.String("openai-api-key", os.Getenv("OPENAI_API_KEY"), "OpenAI API key for natural-language chat")
	openAIBase := flag.String("openai-base", os.Getenv("OPENAI_BASE_URL"), "override OpenAI-compatible Responses API base url")
	openAIModel := flag.String("openai-model", envOrDefault("OPENAI_MODEL", "gpt-5-mini"), "OpenAI model for natural-language chat")
	llmStateFile := flag.String("llm-state-file", "audit/telegram-openai-response.txt", "file storing previous OpenAI response id")
	llmConfirmFile := flag.String("llm-confirm-file", "audit/telegram-openai-confirmation.json", "file base used for pending natural-language confirmations")
	llmMaxToolRounds := flag.Int("llm-max-tool-rounds", 6, "maximum number of tool-calling rounds for one Telegram message")
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
	agent := chatops.Agent{
		OpenAI: chatops.OpenAIClient{
			APIKey:  strings.TrimSpace(*openAIAPIKey),
			BaseURL: strings.TrimSpace(*openAIBase),
			Model:   strings.TrimSpace(*openAIModel),
		},
		OpsAPI:         apiClient,
		State:          chatops.ConversationStateStore{Path: *llmStateFile},
		Confirmations:  chatops.ConfirmationStore{Path: *llmConfirmFile},
		AuditFile:      *auditFile,
		ApproveTimeout: *approveTimeout,
		MaxToolRounds:  *llmMaxToolRounds,
		ConfirmTTL:     10 * time.Minute,
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

	log.Printf("ops-telegram polling started api=%s chat_id=%d llm_enabled=%t model=%s", *apiBase, *chatID, agent.Enabled(), agent.OpenAI.Model)
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
			if err := handleUpdate(tg, apiClient, agent, update, *chatID, *approveTimeout); err != nil {
				log.Printf("update %d error: %v", update.UpdateID, err)
			}
		}
	}
}

func handleUpdate(tg chatops.TelegramClient, api chatops.OpsAPIClient, agent chatops.Agent, update chatops.Update, allowedChatID int64, approveTimeout int) error {
	switch {
	case update.Message != nil:
		msg := update.Message
		if msg.Chat.ID != allowedChatID {
			return nil
		}
		if strings.TrimSpace(msg.Text) == "" {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		defer cancel()
		actor := actorForUser(msg.From)
		if strings.HasPrefix(strings.TrimSpace(msg.Text), "/") {
			return handleCommandUpdate(ctx, tg, api, agent, *msg, actor, approveTimeout)
		}
		if reply, handled, err := agent.HandleConfirmation(ctx, msg.Text, actor); handled {
			if err != nil {
				return tg.SendMessage(ctx, msg.Chat.ID, "确认处理失败："+err.Error(), nil)
			}
			return tg.SendMessage(ctx, msg.Chat.ID, reply, nil)
		}
		if !agent.Enabled() {
			return tg.SendMessage(ctx, msg.Chat.ID, "LLM 未配置，当前请先使用 /help 查看可用命令。", nil)
		}
		reply, err := agent.Run(ctx, msg.Text, actor)
		if err != nil {
			return tg.SendMessage(ctx, msg.Chat.ID, "LLM 处理失败："+err.Error()+"\n\n你也可以先用 /help 查看命令模式。", nil)
		}
		if strings.TrimSpace(reply) == "" {
			reply = "我这边没有拿到可展示的结果，你可以换个问法，或者先用 /help 看看命令。"
		}
		return tg.SendMessage(ctx, msg.Chat.ID, reply, nil)
	case update.CallbackQuery != nil:
		cb := update.CallbackQuery
		if cb.Message.Chat.ID != allowedChatID {
			_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, "unauthorized")
			return nil
		}
		if agent.Enabled() {
			_ = agent.ResetActor(actorForUser(cb.From))
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

func handleCommandUpdate(ctx context.Context, tg chatops.TelegramClient, api chatops.OpsAPIClient, agent chatops.Agent, msg chatops.Message, actor string, approveTimeout int) error {
	cmd, err := chatops.ParseCommand(msg.Text)
	if agent.Enabled() {
		_ = agent.ResetActor(actor)
	}
	if err != nil {
		return tg.SendMessage(ctx, msg.Chat.ID, err.Error()+"\n\n"+chatops.HelpText(), nil)
	}
	if cmd.Name == "reset" {
		return tg.SendMessage(ctx, msg.Chat.ID, "LLM 上下文已重置。", nil)
	}
	reply, markup := executeCommand(ctx, api, cmd, actor, approveTimeout)
	if strings.TrimSpace(reply) == "" {
		return nil
	}
	return tg.SendMessage(ctx, msg.Chat.ID, reply, markup)
}

func handleCommand(ctx context.Context, api chatops.OpsAPIClient, text, actor string, approveTimeout int) (string, any) {
	cmd, err := chatops.ParseCommand(text)
	if err != nil {
		return err.Error() + "\n\n" + chatops.HelpText(), nil
	}
	return executeCommand(ctx, api, cmd, actor, approveTimeout)
}

func executeCommand(ctx context.Context, api chatops.OpsAPIClient, cmd chatops.Command, actor string, approveTimeout int) (string, any) {
	switch cmd.Name {
	case "start", "help":
		return chatops.HelpText(), nil
	case "reset":
		return "LLM 上下文已重置。", nil
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

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

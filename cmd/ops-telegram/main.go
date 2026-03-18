package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/chatops"
	"github.com/alan666gg/ops-agent/internal/config"
)

func main() {
	apiBase := flag.String("api-base", "http://127.0.0.1:8090", "ops-api base url")
	apiToken := flag.String("api-token", os.Getenv("OPS_API_TOKEN"), "ops-api bearer token")
	envFile := flag.String("env-file", "configs/environments.yaml", "environment config file used to resolve env -> project authorization")
	botToken := flag.String("bot-token", os.Getenv("OPS_TG_BOT_TOKEN"), "telegram bot token")
	chatID := flag.Int64("chat-id", 0, "authorized telegram chat id")
	offsetFile := flag.String("offset-file", "audit/telegram-offset.txt", "telegram long-poll offset state file")
	pollTimeout := flag.Duration("poll-timeout", 20*time.Second, "telegram getUpdates long poll timeout")
	approveTimeout := flag.Int("approve-timeout-seconds", 30, "timeout passed to /actions/approve")
	telegramBase := flag.String("telegram-base", "", "override telegram api base url")
	auditFile := flag.String("audit", "audit/telegram.jsonl", "audit output jsonl for telegram chatops and llm actions")
	chatopsConfig := flag.String("chatops-config", "configs/chatops.yaml", "chatops security config file")
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
	securityCfg, err := chatops.LoadSecurityConfig(strings.TrimSpace(*chatopsConfig))
	if err != nil {
		log.Fatal(err)
	}
	authorizer := chatops.NewAuthorizer(securityCfg)
	agent := chatops.Agent{
		OpenAI: chatops.OpenAIClient{
			APIKey:  strings.TrimSpace(*openAIAPIKey),
			BaseURL: strings.TrimSpace(*openAIBase),
			Model:   strings.TrimSpace(*openAIModel),
		},
		OpsAPI:     apiClient,
		Authorizer: authorizer,
		ProjectForEnv: func(env string) (string, error) {
			cfg, err := config.LoadEnvironments(strings.TrimSpace(*envFile))
			if err != nil {
				return "", err
			}
			if _, ok := cfg.Environment(env); !ok {
				return "", fmt.Errorf("env not found: %s", env)
			}
			return cfg.ProjectForEnv(env), nil
		},
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

	log.Printf("ops-telegram polling started api=%s chat_id=%d llm_enabled=%t model=%s chatops_users=%d", *apiBase, *chatID, agent.Enabled(), agent.OpenAI.Model, authorizer.UserCount())
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
			if err := handleUpdate(tg, apiClient, agent, *auditFile, update, *chatID, *approveTimeout); err != nil {
				log.Printf("update %d error: %v", update.UpdateID, err)
			}
		}
	}
}

func handleUpdate(tg chatops.TelegramClient, api chatops.OpsAPIClient, agent chatops.Agent, auditFile string, update chatops.Update, allowedChatID int64, approveTimeout int) error {
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
			return handleCommandUpdate(ctx, tg, api, agent, auditFile, *msg, actor, approveTimeout)
		}
		if err := agent.Authorizer.AuthorizeInput(actor, msg.Text); err != nil {
			emitChatopsAudit(auditFile, actor, "chatops_input", "blocked", err.Error())
			return tg.SendMessage(ctx, msg.Chat.ID, "请求被安全策略拦截："+err.Error(), nil)
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
		var markup any
		if agent.HasPendingConfirmation(actor) {
			markup = chatops.ConfirmationMarkup()
		}
		return tg.SendMessage(ctx, msg.Chat.ID, reply, markup)
	case update.CallbackQuery != nil:
		cb := update.CallbackQuery
		if cb.Message.Chat.ID != allowedChatID {
			_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, "unauthorized")
			return nil
		}
		actor := actorForUser(cb.From)
		if err := agent.Authorizer.AuthorizeCallback(actor, cb.Data); err != nil {
			emitChatopsAudit(auditFile, actor, "chatops_callback", "denied", err.Error())
			_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, trimCallback(err.Error()))
			return tg.SendMessage(context.Background(), cb.Message.Chat.ID, "callback denied: "+err.Error(), nil)
		}
		if agent.Enabled() && cb.Data != "llm_confirm" && cb.Data != "llm_cancel" {
			_ = agent.ResetActor(actor)
		}
		reply, markup, err := handleCallback(context.Background(), api, agent, cb.Data, actor, approveTimeout)
		if err != nil {
			_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, trimCallback(err.Error()))
			return tg.SendMessage(context.Background(), cb.Message.Chat.ID, "callback failed: "+err.Error(), nil)
		}
		_ = tg.AnswerCallbackQuery(context.Background(), cb.ID, trimCallback(reply))
		return tg.SendMessage(context.Background(), cb.Message.Chat.ID, reply, markup)
	default:
		return nil
	}
}

func handleCommandUpdate(ctx context.Context, tg chatops.TelegramClient, api chatops.OpsAPIClient, agent chatops.Agent, auditFile string, msg chatops.Message, actor string, approveTimeout int) error {
	cmd, err := chatops.ParseCommand(msg.Text)
	if agent.Enabled() {
		_ = agent.ResetActor(actor)
	}
	if err != nil {
		return tg.SendMessage(ctx, msg.Chat.ID, err.Error()+"\n\n"+chatops.HelpText(), nil)
	}
	if err := agent.Authorizer.AuthorizeCommand(actor, cmd); err != nil {
		emitChatopsAudit(auditFile, actor, "chatops_command", "denied", err.Error())
		return tg.SendMessage(ctx, msg.Chat.ID, "command denied: "+err.Error(), nil)
	}
	if cmd.Name == "reset" {
		return tg.SendMessage(ctx, msg.Chat.ID, "LLM 上下文已重置。", nil)
	}
	reply, markup := executeCommand(ctx, api, agent, cmd, actor, approveTimeout)
	if strings.TrimSpace(reply) == "" {
		return nil
	}
	return tg.SendMessage(ctx, msg.Chat.ID, reply, markup)
}

func handleCommand(ctx context.Context, api chatops.OpsAPIClient, agent chatops.Agent, text, actor string, approveTimeout int) (string, any) {
	cmd, err := chatops.ParseCommand(text)
	if err != nil {
		return err.Error() + "\n\n" + chatops.HelpText(), nil
	}
	return executeCommand(ctx, api, agent, cmd, actor, approveTimeout)
}

func executeCommand(ctx context.Context, api chatops.OpsAPIClient, agent chatops.Agent, cmd chatops.Command, actor string, approveTimeout int) (string, any) {
	switch cmd.Name {
	case "start", "help":
		return chatops.HelpText(), nil
	case "reset":
		return "LLM 上下文已重置。", nil
	case "health":
		if _, err := authorizeCommandEnv(agent, actor, cmd.Env); err != nil {
			return "health denied: " + err.Error(), nil
		}
		resp, err := api.Health(ctx, cmd.Env)
		if err != nil {
			return "health failed: " + err.Error(), nil
		}
		return chatops.FormatHealth(resp), nil
	case "promql":
		if _, err := authorizeCommandEnv(agent, actor, cmd.Env); err != nil {
			return "prometheus query denied: " + err.Error(), nil
		}
		resp, err := api.PrometheusQuery(ctx, cmd.Env, cmd.Query, cmd.Minutes, cmd.Step)
		if err != nil {
			return "prometheus query failed: " + err.Error(), nil
		}
		return chatops.FormatPrometheusQuery(resp), nil
	case "incidents":
		projects, err := agent.Authorizer.AllowedProjects(actor)
		if err != nil {
			return "incident summary denied: " + err.Error(), nil
		}
		resp, err := api.IncidentSummaryByProject(ctx, cmd.Minutes, projects)
		if err != nil {
			return "incident summary failed: " + err.Error(), nil
		}
		return chatops.FormatIncidentSummary(resp), nil
	case "active":
		projects, err := agent.Authorizer.AllowedProjects(actor)
		if err != nil {
			return "active incidents denied: " + err.Error(), nil
		}
		resp, err := api.ActiveIncidents(ctx, 10, cmd.Env, projects)
		if err != nil {
			return "active incidents failed: " + err.Error(), nil
		}
		return chatops.FormatActiveIncidents(resp), chatops.IncidentListMarkup(resp.Items)
	case "incident":
		item, err := api.GetIncident(ctx, cmd.IncidentID)
		if err != nil {
			return "incident detail failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "incident detail denied: " + err.Error(), nil
		}
		return chatops.FormatIncidentDetail(item), chatops.IncidentMarkup(item)
	case "timeline":
		item, err := api.GetIncidentTimeline(ctx, cmd.IncidentID, cmd.Minutes)
		if err != nil {
			return "incident timeline failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Incident.Project); err != nil {
			return "incident timeline denied: " + err.Error(), nil
		}
		return chatops.FormatIncidentTimeline(item), chatops.IncidentMarkup(item.Incident)
	case "pending":
		projects, err := agent.Authorizer.AllowedProjects(actor)
		if err != nil {
			return "pending query denied: " + err.Error(), nil
		}
		resp, err := api.PendingByProject(ctx, 10, projects)
		if err != nil {
			return "pending query failed: " + err.Error(), nil
		}
		return chatops.FormatPending(resp), chatops.PendingMarkup(resp.Items)
	case "requests":
		projects, err := agent.Authorizer.AllowedProjects(actor)
		if err != nil {
			return "actions query denied: " + err.Error(), nil
		}
		resp, err := api.ListActionsByProject(ctx, cmd.Status, 10, "", projects)
		if err != nil {
			return "actions query failed: " + err.Error(), nil
		}
		return chatops.FormatActionList(resp), nil
	case "show":
		item, err := api.GetAction(ctx, cmd.RequestID)
		if err != nil {
			return "show request failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "show request denied: " + err.Error(), nil
		}
		return chatops.FormatActionDetail(item), chatops.ActionMarkup(item)
	case "approve":
		item, err := api.GetAction(ctx, cmd.RequestID)
		if err != nil {
			return "approve failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "approve denied: " + err.Error(), nil
		}
		resp, err := api.Approve(ctx, cmd.RequestID, actor, approveTimeout)
		if err != nil {
			return "approve failed: " + err.Error(), nil
		}
		return fmt.Sprintf("approved %s\nstatus=%s\nmessage=%s", cmd.RequestID, resp.Status, strings.TrimSpace(resp.Message)), nil
	case "reject":
		item, err := api.GetAction(ctx, cmd.RequestID)
		if err != nil {
			return "reject failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "reject denied: " + err.Error(), nil
		}
		resp, err := api.Reject(ctx, cmd.RequestID, actor, cmd.Reason)
		if err != nil {
			return "reject failed: " + err.Error(), nil
		}
		return fmt.Sprintf("rejected %s\nstatus=%s\nmessage=%s", cmd.RequestID, resp.Status, strings.TrimSpace(resp.Message)), nil
	case "ack":
		item, err := api.GetIncident(ctx, cmd.IncidentID)
		if err != nil {
			return "ack failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "ack denied: " + err.Error(), nil
		}
		updated, err := api.AckIncident(ctx, cmd.IncidentID, actor, cmd.Reason)
		if err != nil {
			return "ack failed: " + err.Error(), nil
		}
		return chatops.FormatIncidentDetail(updated), chatops.IncidentMarkup(updated)
	case "unsilence":
		item, err := api.GetIncident(ctx, cmd.IncidentID)
		if err != nil {
			return "unsilence failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "unsilence denied: " + err.Error(), nil
		}
		updated, err := api.UnsilenceIncident(ctx, cmd.IncidentID, actor, cmd.Reason)
		if err != nil {
			return "unsilence failed: " + err.Error(), nil
		}
		return chatops.FormatIncidentDetail(updated), chatops.IncidentMarkup(updated)
	case "assign":
		item, err := api.GetIncident(ctx, cmd.IncidentID)
		if err != nil {
			return "assign failed: " + err.Error(), nil
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "assign denied: " + err.Error(), nil
		}
		updated, err := api.AssignIncident(ctx, cmd.IncidentID, cmd.Owner, actor, cmd.Reason)
		if err != nil {
			return "assign failed: " + err.Error(), nil
		}
		return chatops.FormatIncidentDetail(updated), chatops.IncidentMarkup(updated)
	case "request":
		if _, err := authorizeCommandEnv(agent, actor, cmd.Env); err != nil {
			return "request denied: " + err.Error(), nil
		}
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

func handleCallback(ctx context.Context, api chatops.OpsAPIClient, agent chatops.Agent, data, actor string, approveTimeout int) (string, any, error) {
	switch {
	case data == "llm_confirm":
		reply, _, err := agent.HandleConfirmation(ctx, "确认执行", actor)
		return reply, nil, err
	case data == "llm_cancel":
		reply, _, err := agent.HandleConfirmation(ctx, "取消", actor)
		return reply, nil, err
	case strings.HasPrefix(data, "show:"):
		id := strings.TrimPrefix(data, "show:")
		item, err := api.GetAction(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		return chatops.FormatActionDetail(item), chatops.ActionMarkup(item), nil
	case strings.HasPrefix(data, "incident_show:"):
		id := strings.TrimPrefix(data, "incident_show:")
		item, err := api.GetIncident(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		return chatops.FormatIncidentDetail(item), chatops.IncidentMarkup(item), nil
	case strings.HasPrefix(data, "incident_timeline:"):
		id := strings.TrimPrefix(data, "incident_timeline:")
		item, err := api.GetIncidentTimeline(ctx, id, 90)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Incident.Project); err != nil {
			return "", nil, err
		}
		return chatops.FormatIncidentTimeline(item), chatops.IncidentMarkup(item.Incident), nil
	case strings.HasPrefix(data, "incident_ack:"):
		id := strings.TrimPrefix(data, "incident_ack:")
		item, err := api.GetIncident(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		updated, err := api.AckIncident(ctx, id, actor, "acknowledged from telegram button")
		if err != nil {
			return "", nil, err
		}
		return chatops.FormatIncidentDetail(updated), chatops.IncidentMarkup(updated), nil
	case strings.HasPrefix(data, "incident_unsilence:"):
		id := strings.TrimPrefix(data, "incident_unsilence:")
		item, err := api.GetIncident(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		updated, err := api.UnsilenceIncident(ctx, id, actor, "expired from telegram button")
		if err != nil {
			return "", nil, err
		}
		return chatops.FormatIncidentDetail(updated), chatops.IncidentMarkup(updated), nil
	case strings.HasPrefix(data, "incident_assign:"):
		id := strings.TrimPrefix(data, "incident_assign:")
		item, err := api.GetIncident(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		updated, err := api.AssignIncident(ctx, id, actor, actor, "claimed from telegram button")
		if err != nil {
			return "", nil, err
		}
		return chatops.FormatIncidentDetail(updated), chatops.IncidentMarkup(updated), nil
	case strings.HasPrefix(data, "approve:"):
		id := strings.TrimPrefix(data, "approve:")
		item, err := api.GetAction(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		resp, err := api.Approve(ctx, id, actor, approveTimeout)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("approved %s\nstatus=%s", id, resp.Status), nil, nil
	case strings.HasPrefix(data, "reject:"):
		id := strings.TrimPrefix(data, "reject:")
		item, err := api.GetAction(ctx, id)
		if err != nil {
			return "", nil, err
		}
		if err := agent.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return "", nil, err
		}
		resp, err := api.Reject(ctx, id, actor, "rejected from telegram button")
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("rejected %s\nstatus=%s", id, resp.Status), nil, nil
	default:
		return "", nil, fmt.Errorf("unsupported callback")
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

func emitChatopsAudit(path, actor, action, status, message string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = audit.AppendJSONL(path, audit.Event{
		Time:    time.Now().UTC(),
		Actor:   actor,
		Action:  action,
		Status:  status,
		Message: message,
		Target:  "telegram",
	})
}

func authorizeCommandEnv(agent chatops.Agent, actor, env string) (string, error) {
	if agent.ProjectForEnv == nil {
		return "default", nil
	}
	project, err := agent.ProjectForEnv(env)
	if err != nil {
		return "", err
	}
	if err := agent.Authorizer.AuthorizeProject(actor, project); err != nil {
		return "", err
	}
	return project, nil
}

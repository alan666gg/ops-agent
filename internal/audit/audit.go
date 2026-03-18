package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
)

type Event struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Env        string    `json:"env,omitempty"`
	TargetHost string    `json:"target_host,omitempty"`
	Target     string    `json:"target,omitempty"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	RequiresOK bool      `json:"requires_approval,omitempty"`
}

func AppendJSONL(path string, evt Event) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(evt)
}

func CountRecentAutoActions(path, env string, since time.Time) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var evt Event
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			continue
		}
		if evt.Time.Before(since) {
			continue
		}
		if strings.TrimSpace(evt.Env) != strings.TrimSpace(env) {
			continue
		}
		if evt.RequiresOK {
			continue
		}
		if _, ok := actions.Lookup(evt.Action); !ok {
			continue
		}
		switch evt.Status {
		case "ok", "failed", "executed":
			count++
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

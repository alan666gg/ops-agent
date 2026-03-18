package audit

import (
	"encoding/json"
	"os"
	"time"
)

type Event struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
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

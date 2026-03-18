package slo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
)

type Evaluator struct {
	Now func() time.Time
}

type windowStats struct {
	Total  int
	Errors int
}

type serviceStats struct {
	PageShort   windowStats
	PageLong    windowStats
	TicketShort windowStats
	TicketLong  windowStats
}

type serviceRef struct {
	name   string
	target string
	slo    config.ServiceSLO
}

func (e Evaluator) EvaluateAvailability(path, envName string, env config.Environment) ([]checks.Result, error) {
	var services []serviceRef
	var earliest time.Time
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}

	targets := map[string]serviceRef{}
	for _, svc := range env.Services {
		if !svc.SLO.Enabled() {
			continue
		}
		sloCfg := svc.SLO.WithDefaults()
		ref := serviceRef{
			name:   svc.Name,
			target: "service_" + sanitizeName(svc.Name),
			slo:    sloCfg,
		}
		services = append(services, ref)
		targets[ref.target] = ref
		since := now.Add(-maxDuration(sloCfg.PageLongWindow, sloCfg.TicketLongWindow))
		if earliest.IsZero() || since.Before(earliest) {
			earliest = since
		}
	}
	if len(services) == 0 {
		return nil, nil
	}

	stats := map[string]*serviceStats{}
	for _, ref := range services {
		stats[ref.target] = &serviceStats{}
	}
	if err := scanAvailability(path, envName, earliest, now, targets, stats); err != nil {
		return nil, err
	}

	out := make([]checks.Result, 0, len(services))
	for _, ref := range services {
		res, ok := evaluateService(ref, stats[ref.target])
		if ok {
			out = append(out, res)
		}
	}
	return out, nil
}

func scanAvailability(path, envName string, earliest, now time.Time, targets map[string]serviceRef, stats map[string]*serviceStats) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var evt audit.Event
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			continue
		}
		if evt.Time.Before(earliest) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(evt.Env), strings.TrimSpace(envName)) {
			continue
		}
		if evt.Action != "health_run" && evt.Action != "health_cycle" {
			continue
		}
		targetName := strings.TrimPrefix(strings.TrimSpace(evt.Target), strings.TrimSpace(envName)+"/")
		ref, ok := targets[targetName]
		if !ok {
			continue
		}
		serviceStats := stats[targetName]
		isError := healthEventError(evt.Status)
		if evt.Time.After(now.Add(-ref.slo.PageLongWindow)) || evt.Time.Equal(now.Add(-ref.slo.PageLongWindow)) {
			recordSample(&serviceStats.PageLong, isError)
		}
		if evt.Time.After(now.Add(-ref.slo.PageShortWindow)) || evt.Time.Equal(now.Add(-ref.slo.PageShortWindow)) {
			recordSample(&serviceStats.PageShort, isError)
		}
		if evt.Time.After(now.Add(-ref.slo.TicketLongWindow)) || evt.Time.Equal(now.Add(-ref.slo.TicketLongWindow)) {
			recordSample(&serviceStats.TicketLong, isError)
		}
		if evt.Time.After(now.Add(-ref.slo.TicketShortWindow)) || evt.Time.Equal(now.Add(-ref.slo.TicketShortWindow)) {
			recordSample(&serviceStats.TicketShort, isError)
		}
	}
	return sc.Err()
}

func evaluateService(ref serviceRef, stats *serviceStats) (checks.Result, bool) {
	if stats == nil {
		return checks.Result{}, false
	}
	errorBudget := (100.0 - ref.slo.AvailabilityTarget) / 100.0
	if errorBudget <= 0 {
		return checks.Result{}, false
	}
	pageShortBR := burnRate(stats.PageShort, errorBudget)
	pageLongBR := burnRate(stats.PageLong, errorBudget)
	ticketShortBR := burnRate(stats.TicketShort, errorBudget)
	ticketLongBR := burnRate(stats.TicketLong, errorBudget)

	pageReady := stats.PageLong.Total >= ref.slo.MinSamples && stats.PageShort.Total > 0
	ticketReady := stats.TicketLong.Total >= ref.slo.MinSamples && stats.TicketShort.Total > 0

	name := "slo_availability_" + sanitizeName(ref.name)
	if !pageReady && !ticketReady {
		return checks.Result{}, false
	}

	msg := fmt.Sprintf("availability target=%.3f%% page burn short=%.2f long=%.2f ticket burn short=%.2f long=%.2f samples(page=%d/%d ticket=%d/%d)",
		ref.slo.AvailabilityTarget,
		pageShortBR,
		pageLongBR,
		ticketShortBR,
		ticketLongBR,
		stats.PageShort.Total,
		stats.PageLong.Total,
		stats.TicketShort.Total,
		stats.TicketLong.Total,
	)

	switch {
	case pageReady && pageShortBR >= ref.slo.PageBurnRate && pageLongBR >= ref.slo.PageBurnRate:
		return checks.Result{
			Name:     name,
			Code:     "SLO_BURN_FAST",
			Message:  msg,
			Action:   "inspect user impact, recent deploys, and rollback readiness",
			Severity: checks.SeverityFail,
		}, true
	case ticketReady && ticketShortBR >= ref.slo.TicketBurnRate && ticketLongBR >= ref.slo.TicketBurnRate:
		return checks.Result{
			Name:     name,
			Code:     "SLO_BURN_SLOW",
			Message:  msg,
			Action:   "inspect service reliability trend and error budget consumption",
			Severity: checks.SeverityWarn,
		}, true
	default:
		return checks.Result{
			Name:     name,
			Code:     "SLO_OK",
			Message:  msg,
			Severity: checks.SeverityPass,
		}, true
	}
}

func recordSample(stats *windowStats, isError bool) {
	stats.Total++
	if isError {
		stats.Errors++
	}
}

func burnRate(stats windowStats, errorBudget float64) float64 {
	if stats.Total == 0 || errorBudget <= 0 {
		return 0
	}
	return (float64(stats.Errors) / float64(stats.Total)) / errorBudget
}

func healthEventError(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok", "pass":
		return false
	default:
		return true
	}
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

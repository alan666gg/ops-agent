package incident

import (
	"sort"
	"strings"
	"time"
)

type Stats struct {
	TotalRecords         int            `json:"total_records"`
	OpenRecords          int            `json:"open_records"`
	ResolvedRecords      int            `json:"resolved_records"`
	AcknowledgedRecords  int            `json:"acknowledged_records"`
	AssignedRecords      int            `json:"assigned_records"`
	SilencedRecords      int            `json:"silenced_records"`
	OpenCount            int            `json:"open_count"`
	ReopenCount          int            `json:"reopen_count"`
	ResolutionCount      int            `json:"resolution_count"`
	AckCount             int            `json:"ack_count"`
	AvgMTTASeconds       float64        `json:"avg_mtta_seconds,omitempty"`
	AvgMTTRSeconds       float64        `json:"avg_mttr_seconds,omitempty"`
	OldestOpenAgeSeconds float64        `json:"oldest_open_age_seconds,omitempty"`
	ByStatus             map[string]int `json:"by_status,omitempty"`
	BySource             map[string]int `json:"by_source,omitempty"`
}

type ScopeStats struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Source  string `json:"source,omitempty"`
	Stats   Stats  `json:"stats"`
}

func ComputeStats(records []Record, now time.Time) Stats {
	now = now.UTC()
	out := Stats{
		ByStatus: map[string]int{},
		BySource: map[string]int{},
	}
	var totalAckSeconds float64
	var totalOpenSeconds float64
	for _, rec := range records {
		out.TotalRecords++
		out.ByStatus[strings.TrimSpace(rec.Status)]++
		out.BySource[strings.TrimSpace(rec.Source)]++
		if rec.Open {
			out.OpenRecords++
			if !rec.FirstSeenAt.IsZero() && now.After(rec.FirstSeenAt) {
				age := now.Sub(rec.FirstSeenAt).Seconds()
				if age > out.OldestOpenAgeSeconds {
					out.OldestOpenAgeSeconds = age
				}
			}
		} else {
			out.ResolvedRecords++
		}
		if rec.Acknowledged {
			out.AcknowledgedRecords++
		}
		if strings.TrimSpace(rec.Owner) != "" {
			out.AssignedRecords++
		}
		if SilenceActive(rec.Silence, now) {
			out.SilencedRecords++
		}
		out.OpenCount += rec.OpenCount
		out.ReopenCount += rec.ReopenCount
		out.ResolutionCount += rec.ResolutionCount
		out.AckCount += rec.AckCount
		totalAckSeconds += rec.TotalAckSeconds
		totalOpenSeconds += rec.TotalOpenSeconds
	}
	if out.AckCount > 0 {
		out.AvgMTTASeconds = totalAckSeconds / float64(out.AckCount)
	}
	if out.ResolutionCount > 0 {
		out.AvgMTTRSeconds = totalOpenSeconds / float64(out.ResolutionCount)
	}
	return out
}

func GroupStats(records []Record, now time.Time) []ScopeStats {
	type key struct {
		project string
		env     string
		source  string
	}
	grouped := map[key][]Record{}
	for _, rec := range records {
		k := key{
			project: defaultProject(rec.Project),
			env:     strings.TrimSpace(rec.Env),
			source:  strings.TrimSpace(rec.Source),
		}
		grouped[k] = append(grouped[k], rec)
	}
	out := make([]ScopeStats, 0, len(grouped))
	for k, items := range grouped {
		out = append(out, ScopeStats{
			Project: k.project,
			Env:     k.env,
			Source:  k.source,
			Stats:   ComputeStats(items, now),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		if out[i].Env != out[j].Env {
			return out[i].Env < out[j].Env
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func LifecycleTransition(rec Record) string {
	switch {
	case rec.Open && rec.OpenCount == 1 && rec.FirstSeenAt.Equal(rec.LastChangedAt):
		return "opened"
	case rec.Open && rec.ReopenCount > 0 && rec.FirstSeenAt.Equal(rec.LastChangedAt):
		return "reopened"
	case !rec.Open && !rec.ClosedAt.IsZero() && rec.ClosedAt.Equal(rec.LastChangedAt):
		return "resolved"
	default:
		return "updated"
	}
}

package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
}

type Sample struct {
	Time  time.Time `json:"time"`
	Value string    `json:"value"`
}

type Series struct {
	Metric map[string]string `json:"metric,omitempty"`
	Value  *Sample           `json:"value,omitempty"`
	Values []Sample          `json:"values,omitempty"`
}

type QueryResponse struct {
	Query         string   `json:"query"`
	ResultType    string   `json:"result_type"`
	Range         bool     `json:"range"`
	WindowMinutes int      `json:"window_minutes,omitempty"`
	Step          string   `json:"step,omitempty"`
	Series        []Series `json:"series,omitempty"`
	Scalar        *Sample  `json:"scalar,omitempty"`
	String        *Sample  `json:"string,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	Summary       string   `json:"summary,omitempty"`
}

type apiEnvelope struct {
	Status    string   `json:"status"`
	Data      apiData  `json:"data"`
	ErrorType string   `json:"errorType"`
	Error     string   `json:"error"`
	Warnings  []string `json:"warnings,omitempty"`
}

type apiData struct {
	ResultType string          `json:"resultType"`
	Result     json.RawMessage `json:"result"`
}

func (c Client) QueryInstant(ctx context.Context, query string, at time.Time) (QueryResponse, error) {
	values := url.Values{}
	values.Set("query", strings.TrimSpace(query))
	if !at.IsZero() {
		values.Set("time", formatAPITime(at.UTC()))
	}
	resp, err := c.do(ctx, "/api/v1/query", values)
	if err != nil {
		return QueryResponse{}, err
	}
	out, err := parseQueryResponse(strings.TrimSpace(query), resp)
	if err != nil {
		return QueryResponse{}, err
	}
	out.Range = false
	out.Summary = Summarize(out)
	return out, nil
}

func (c Client) QueryRange(ctx context.Context, query string, start, end time.Time, step time.Duration) (QueryResponse, error) {
	if step <= 0 {
		step = 1 * time.Minute
	}
	values := url.Values{}
	values.Set("query", strings.TrimSpace(query))
	values.Set("start", formatAPITime(start.UTC()))
	values.Set("end", formatAPITime(end.UTC()))
	values.Set("step", strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
	resp, err := c.do(ctx, "/api/v1/query_range", values)
	if err != nil {
		return QueryResponse{}, err
	}
	out, err := parseQueryResponse(strings.TrimSpace(query), resp)
	if err != nil {
		return QueryResponse{}, err
	}
	out.Range = true
	out.WindowMinutes = int(end.Sub(start) / time.Minute)
	out.Step = step.String()
	out.Summary = Summarize(out)
	return out, nil
}

func (c Client) do(ctx context.Context, path string, values url.Values) (apiEnvelope, error) {
	if strings.TrimSpace(c.BaseURL) == "" {
		return apiEnvelope{}, fmt.Errorf("prometheus base url is required")
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	fullURL := strings.TrimRight(c.BaseURL, "/") + path + "?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return apiEnvelope{}, err
	}
	if strings.TrimSpace(c.BearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.BearerToken))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return apiEnvelope{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return apiEnvelope{}, err
	}
	var out apiEnvelope
	if err := json.Unmarshal(b, &out); err != nil {
		return apiEnvelope{}, err
	}
	if resp.StatusCode >= 400 {
		if strings.TrimSpace(out.Error) != "" {
			return apiEnvelope{}, fmt.Errorf("prometheus query failed: %s", out.Error)
		}
		return apiEnvelope{}, fmt.Errorf("prometheus query failed: http %d", resp.StatusCode)
	}
	if strings.TrimSpace(out.Status) != "success" {
		if strings.TrimSpace(out.Error) != "" {
			return apiEnvelope{}, fmt.Errorf("prometheus query failed: %s", out.Error)
		}
		return apiEnvelope{}, fmt.Errorf("prometheus query failed: status=%s", out.Status)
	}
	return out, nil
}

func parseQueryResponse(query string, env apiEnvelope) (QueryResponse, error) {
	out := QueryResponse{
		Query:      query,
		ResultType: strings.TrimSpace(env.Data.ResultType),
		Warnings:   append([]string(nil), env.Warnings...),
	}
	switch out.ResultType {
	case "vector":
		series, err := parseSeriesVector(env.Data.Result)
		if err != nil {
			return QueryResponse{}, err
		}
		out.Series = series
	case "matrix":
		series, err := parseSeriesMatrix(env.Data.Result)
		if err != nil {
			return QueryResponse{}, err
		}
		out.Series = series
	case "scalar":
		sample, err := parseScalarLike(env.Data.Result)
		if err != nil {
			return QueryResponse{}, err
		}
		out.Scalar = &sample
	case "string":
		sample, err := parseScalarLike(env.Data.Result)
		if err != nil {
			return QueryResponse{}, err
		}
		out.String = &sample
	default:
		return QueryResponse{}, fmt.Errorf("unsupported prometheus result type %q", out.ResultType)
	}
	return out, nil
}

func parseSeriesVector(raw json.RawMessage) ([]Series, error) {
	var rows []struct {
		Metric map[string]string `json:"metric"`
		Value  []any             `json:"value"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(rows))
	for _, row := range rows {
		sample, err := parseSampleTuple(row.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, Series{
			Metric: row.Metric,
			Value:  &sample,
		})
	}
	sortSeries(out)
	return out, nil
}

func parseSeriesMatrix(raw json.RawMessage) ([]Series, error) {
	var rows []struct {
		Metric map[string]string `json:"metric"`
		Values [][]any           `json:"values"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(rows))
	for _, row := range rows {
		values := make([]Sample, 0, len(row.Values))
		for _, tuple := range row.Values {
			sample, err := parseSampleTuple(tuple)
			if err != nil {
				return nil, err
			}
			values = append(values, sample)
		}
		out = append(out, Series{
			Metric: row.Metric,
			Values: values,
		})
	}
	sortSeries(out)
	return out, nil
}

func parseScalarLike(raw json.RawMessage) (Sample, error) {
	var tuple []any
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return Sample{}, err
	}
	return parseSampleTuple(tuple)
}

func parseSampleTuple(tuple []any) (Sample, error) {
	if len(tuple) != 2 {
		return Sample{}, fmt.Errorf("expected prometheus sample tuple")
	}
	ts, err := parseTimestamp(tuple[0])
	if err != nil {
		return Sample{}, err
	}
	return Sample{
		Time:  ts,
		Value: stringFromTupleValue(tuple[1]),
	}, nil
}

func parseTimestamp(v any) (time.Time, error) {
	switch x := v.(type) {
	case float64:
		sec := int64(x)
		nsec := int64((x - float64(sec)) * float64(time.Second))
		return time.Unix(sec, nsec).UTC(), nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return time.Time{}, err
		}
		sec := int64(f)
		nsec := int64((f - float64(sec)) * float64(time.Second))
		return time.Unix(sec, nsec).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type %T", v)
	}
}

func stringFromTupleValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func Summarize(resp QueryResponse) string {
	switch resp.ResultType {
	case "scalar":
		if resp.Scalar == nil {
			return "prometheus scalar query returned no sample"
		}
		return fmt.Sprintf("scalar=%s at %s", resp.Scalar.Value, resp.Scalar.Time.UTC().Format(time.RFC3339))
	case "string":
		if resp.String == nil {
			return "prometheus string query returned no sample"
		}
		return fmt.Sprintf("string=%s at %s", resp.String.Value, resp.String.Time.UTC().Format(time.RFC3339))
	case "vector":
		if len(resp.Series) == 0 {
			return "vector query returned 0 series"
		}
		return fmt.Sprintf("vector query returned %d series; top=%s", len(resp.Series), formatSeriesSummary(resp.Series[0]))
	case "matrix":
		if len(resp.Series) == 0 {
			return "range query returned 0 series"
		}
		return fmt.Sprintf("range query returned %d series over %dm step=%s; top=%s", len(resp.Series), resp.WindowMinutes, defaultString(resp.Step, "auto"), formatSeriesSummary(resp.Series[0]))
	default:
		return "prometheus query completed"
	}
}

func AutoStep(window time.Duration) time.Duration {
	switch {
	case window <= 30*time.Minute:
		return 30 * time.Second
	case window <= 2*time.Hour:
		return 1 * time.Minute
	case window <= 6*time.Hour:
		return 5 * time.Minute
	case window <= 24*time.Hour:
		return 15 * time.Minute
	default:
		return 1 * time.Hour
	}
}

func formatSeriesSummary(series Series) string {
	metric := formatMetric(series.Metric)
	switch {
	case series.Value != nil:
		return fmt.Sprintf("%s=%s", metric, series.Value.Value)
	case len(series.Values) > 0:
		last := series.Values[len(series.Values)-1]
		return fmt.Sprintf("%s last=%s samples=%d", metric, last.Value, len(series.Values))
	default:
		return metric
	}
}

func formatMetric(metric map[string]string) string {
	if len(metric) == 0 {
		return "(no labels)"
	}
	keys := make([]string, 0, len(metric))
	for key := range metric {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+metric[key])
	}
	return strings.Join(parts, ",")
}

func sortSeries(items []Series) {
	sort.SliceStable(items, func(i, j int) bool {
		return formatMetric(items[i].Metric) < formatMetric(items[j].Metric)
	})
}

func formatAPITime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/float64(time.Second), 'f', -1, 64)
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

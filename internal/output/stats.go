package output

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"blackroute/internal/record"
)

type RunStats struct {
	GeneratedAt      string     `json:"generated_at"`
	TotalRecords     int        `json:"total_records"`
	UniqueIPs        int        `json:"unique_ips"`
	UniqueSources    int        `json:"unique_sources"`
	BySource         []CountRow `json:"by_source"`
	ByThreat         []CountRow `json:"by_threat"`
	ByInfrastructure []CountRow `json:"by_infrastructure"`
	ByClassification []CountRow `json:"by_classification"`
	AddedIPs         int        `json:"added_ips"`
	RemovedIPs       int        `json:"removed_ips"`
}

type CountRow struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func WriteRunStats(path string, records []record.Record) error {
	if path == "" {
		return nil
	}
	stats := buildStats(records)
	if prev, err := readPreviousIPs(filepath.Join(filepath.Dir(path), "blackroute.csv")); err == nil {
		cur := currentIPs(records)
		stats.AddedIPs, stats.RemovedIPs = diffCount(cur, prev)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stats); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func buildStats(records []record.Record) RunStats {
	ips := map[string]struct{}{}
	sources := map[string]struct{}{}
	bySource := map[string]int{}
	byThreat := map[string]int{}
	byInfra := map[string]int{}
	byClass := map[string]int{}

	for _, r := range records {
		ips[r.IP] = struct{}{}
		src := r.SourceName
		if src == "" {
			src = "unknown"
		}
		sources[src] = struct{}{}
		bySource[src]++
		for _, v := range r.Threat {
			byThreat[v]++
		}
		for _, v := range r.Infrastructure {
			byInfra[v]++
		}
		for _, v := range r.Classification {
			byClass[v]++
		}
	}

	return RunStats{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		TotalRecords:     len(records),
		UniqueIPs:        len(ips),
		UniqueSources:    len(sources),
		BySource:         countRows(bySource),
		ByThreat:         countRows(byThreat),
		ByInfrastructure: countRows(byInfra),
		ByClassification: countRows(byClass),
	}
}

func countRows(m map[string]int) []CountRow {
	out := make([]CountRow, 0, len(m))
	for k, v := range m {
		out = append(out, CountRow{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func readPreviousIPs(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return map[string]struct{}{}, nil
	}
	ipIdx := -1
	for i, h := range rows[0] {
		if h == "ip" {
			ipIdx = i
			break
		}
	}
	out := map[string]struct{}{}
	if ipIdx < 0 {
		return out, nil
	}
	for _, row := range rows[1:] {
		if ipIdx < len(row) {
			out[row[ipIdx]] = struct{}{}
		}
	}
	return out, nil
}

func currentIPs(records []record.Record) map[string]struct{} {
	ips := map[string]struct{}{}
	for _, r := range records {
		ips[r.IP] = struct{}{}
	}
	return ips
}

func diffCount(cur, prev map[string]struct{}) (added, removed int) {
	for k := range cur {
		if _, ok := prev[k]; !ok {
			added++
		}
	}
	for k := range prev {
		if _, ok := cur[k]; !ok {
			removed++
		}
	}
	return added, removed
}

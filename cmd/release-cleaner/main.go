package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"blackroute/internal/domainx"
	"blackroute/internal/output"
	"blackroute/internal/record"
)

type cleanupStats struct {
	GeneratedAt       string         `json:"generated_at"`
	Policy            string         `json:"policy"`
	InputRecords      int            `json:"input_records"`
	OutputRecords     int            `json:"output_records"`
	RemovedRecords    int            `json:"removed_records"`
	EnabledSources    int            `json:"enabled_sources"`
	RemainingSources  int            `json:"remaining_sources"`
	RemovedByReason   map[string]int `json:"removed_by_reason"`
	RemainingByThreat map[string]int `json:"remaining_by_threat"`
	RemainingByInfra  map[string]int `json:"remaining_by_infrastructure"`
	RemainingByClass  map[string]int `json:"remaining_by_classification"`
	RemainingBySource map[string]int `json:"remaining_by_source"`
}

func main() {
	var (
		releaseDir = flag.String("release", "release", "release directory")
		feedsPath  = flag.String("feeds", "configs/feeds.yaml", "feed configuration")
		summary    = flag.String("summary", "", "markdown summary path")
	)
	flag.Parse()

	csvPath := filepath.Join(*releaseDir, "blackroute.csv")
	records, err := readRecords(csvPath)
	if err != nil {
		die("read records: %v", err)
	}

	enabledSources := countEnabledSources(*feedsPath)
	cleaned, stats := cleanRecords(records)
	stats.EnabledSources = enabledSources
	stats.RemainingSources = len(stats.RemainingBySource)

	if err := output.WriteCSV(csvPath, cleaned); err != nil {
		die("write csv: %v", err)
	}
	if err := output.WriteJSONL(filepath.Join(*releaseDir, "blackroute.jsonl"), cleaned); err != nil {
		die("write jsonl: %v", err)
	}
	if err := output.WriteThreatMMDB(filepath.Join(*releaseDir, "blackroute.mmdb"), cleaned); err != nil {
		die("write mmdb: %v", err)
	}
	if err := output.WriteRunStats(filepath.Join(*releaseDir, "run_stats.json"), cleaned); err != nil {
		die("write stats: %v", err)
	}
	if err := writeJSON(filepath.Join(*releaseDir, "cleanup_stats.json"), stats); err != nil {
		die("write cleanup stats: %v", err)
	}

	summaryPath := *summary
	if summaryPath == "" {
		summaryPath = filepath.Join(*releaseDir, "release_summary.md")
	}
	if err := writeSummary(summaryPath, stats); err != nil {
		die("write summary: %v", err)
	}

	fmt.Printf("Release cleanup complete: %d -> %d records (%d removed)\n", stats.InputRecords, stats.OutputRecords, stats.RemovedRecords)
}

func readRecords(path string) ([]record.Record, error) {
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
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty csv")
	}
	header := map[string]int{}
	for i, h := range rows[0] {
		header[h] = i
	}

	out := make([]record.Record, 0, len(rows)-1)
	for _, row := range rows[1:] {
		rec := record.Record{
			IP:             value(row, header, "ip"),
			SourceName:     value(row, header, "source"),
			Threat:         splitLabels(value(row, header, "threat")),
			Infrastructure: splitLabels(value(row, header, "infrastructure")),
			Classification: splitLabels(value(row, header, "classification")),
			LastSeen:       time.Now().UTC(),
		}
		if raw := value(row, header, "confidence"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				rec.Confidence = n
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

func cleanRecords(records []record.Record) ([]record.Record, cleanupStats) {
	stats := cleanupStats{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Policy:            "BogonForge-compatible public-IP release cleanup",
		InputRecords:      len(records),
		RemovedByReason:   map[string]int{},
		RemainingByThreat: map[string]int{},
		RemainingByInfra:  map[string]int{},
		RemainingByClass:  map[string]int{},
		RemainingBySource: map[string]int{},
	}

	out := make([]record.Record, 0, len(records))
	for _, r := range records {
		if reason := removalReason(r.IP); reason != "" {
			stats.RemovedByReason[reason]++
			continue
		}
		out = append(out, r)
		addCounts(stats.RemainingBySource, []string{sourceName(r.SourceName)})
		addCounts(stats.RemainingByThreat, r.Threat)
		addCounts(stats.RemainingByInfra, r.Infrastructure)
		addCounts(stats.RemainingByClass, r.Classification)
	}

	stats.OutputRecords = len(out)
	stats.RemovedRecords = stats.InputRecords - stats.OutputRecords
	return out, stats
}

func removalReason(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "empty_ip"
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return "invalid_cidr"
		}
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() < domainx.MinV4PrefixBits {
			return "too_wide_ipv4_prefix"
		}
		if !p.Addr().Is4() && p.Bits() < domainx.MinV6PrefixBits {
			return "too_wide_ipv6_prefix"
		}
		if domainx.NormalizePublicCIDR(raw) == "" {
			return "bogon_or_reserved_prefix"
		}
		return ""
	}
	if _, version := domainx.NormalizeIP(raw); version == 0 {
		return "invalid_ip"
	}
	if _, version := domainx.NormalizePublicIP(raw); version == 0 {
		return "bogon_or_reserved_ip"
	}
	return ""
}

func writeSummary(path string, stats cleanupStats) error {
	var b strings.Builder
	b.WriteString("# Blackroute Release Summary\n\n")
	b.WriteString("Release artifacts are cleaned with [BogonForge](https://github.com/ipanalytics/BogonForge)-compatible public IP filtering before publication.\n\n")
	b.WriteString("## Dataset\n\n")
	fmt.Fprintf(&b, "- Configured sources: `%d`\n", stats.EnabledSources)
	fmt.Fprintf(&b, "- Sources remaining after cleanup: `%d`\n", stats.RemainingSources)
	fmt.Fprintf(&b, "- Records before cleanup: `%d`\n", stats.InputRecords)
	fmt.Fprintf(&b, "- Records removed by cleanup: `%d`\n", stats.RemovedRecords)
	fmt.Fprintf(&b, "- Records published: `%d`\n", stats.OutputRecords)
	b.WriteString("\n## Cleanup Policy\n\n")
	b.WriteString("- Removed invalid IPs and CIDRs.\n")
	b.WriteString("- Removed private, loopback, link-local, multicast, unspecified, CGNAT, reserved, and overly broad bogon prefixes.\n")
	b.WriteString("- Rebuilt CSV, JSONL, MMDB, and run stats after cleanup.\n\n")
	writeCountTable(&b, "Removed By Reason", stats.RemovedByReason)
	writeCountTable(&b, "Top Sources", topN(stats.RemainingBySource, 20))
	writeCountTable(&b, "Top Threat Labels", topN(stats.RemainingByThreat, 20))
	writeCountTable(&b, "Top Infrastructure Labels", topN(stats.RemainingByInfra, 20))
	writeCountTable(&b, "Top Classification Labels", topN(stats.RemainingByClass, 20))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeCountTable(b *strings.Builder, title string, counts map[string]int) {
	b.WriteString("## " + title + "\n\n")
	if len(counts) == 0 {
		b.WriteString("No entries.\n\n")
		return
	}
	b.WriteString("| Name | Count |\n| --- | ---: |\n")
	for _, row := range sortedCounts(counts) {
		fmt.Fprintf(b, "| `%s` | %d |\n", row.name, row.count)
	}
	b.WriteString("\n")
}

type countRow struct {
	name  string
	count int
}

func sortedCounts(counts map[string]int) []countRow {
	rows := make([]countRow, 0, len(counts))
	for k, v := range counts {
		rows = append(rows, countRow{name: k, count: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
	return rows
}

func topN(counts map[string]int, n int) map[string]int {
	rows := sortedCounts(counts)
	if len(rows) > n {
		rows = rows[:n]
	}
	out := make(map[string]int, len(rows))
	for _, row := range rows {
		out[row.name] = row.count
	}
	return out
}

func addCounts(counts map[string]int, labels []string) {
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label != "" {
			counts[label]++
		}
	}
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func countEnabledSources(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- kind:") {
			count++
		}
	}
	return count
}

func value(row []string, header map[string]int, name string) string {
	idx, ok := header[name]
	if !ok || idx >= len(row) {
		return ""
	}
	return row[idx]
}

func splitLabels(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sourceName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "unknown"
	}
	return name
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

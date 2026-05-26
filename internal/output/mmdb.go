package output

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"blackroute/internal/record"
)

func WriteThreatMMDB(path string, records []record.Record) error {
	fmt.Println("MMDB schema: blackroute-v1")
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "blackroute",
		IPVersion:    6,
		RecordSize:   28,
		Languages:    []string{"en"},
		Description: map[string]string{
			"en": "Blackroute IP reputation intelligence",
		},
	})
	if err != nil {
		return fmt.Errorf("mmdbwriter.New: %w", err)
	}

	groups := make(map[string][]record.Record, len(records))
	order := make([]string, 0, len(records))
	for _, r := range records {
		key := networkKey(r.IP)
		if key == "" {
			continue
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], r)
	}

	inserted := 0
	for _, key := range order {
		_, network, err := net.ParseCIDR(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", key, err)
			continue
		}
		if err := writer.Insert(network, buildThreatMMDBEntry(key, groups[key])); err != nil {
			fmt.Fprintf(os.Stderr, "  insert %s: %v\n", key, err)
			continue
		}
		inserted++
	}

	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer out.Close()
	if _, err := writer.WriteTo(out); err != nil {
		return fmt.Errorf("write mmdb: %w", err)
	}

	info, _ := os.Stat(path)
	sizeMB := float64(0)
	if info != nil {
		sizeMB = float64(info.Size()) / (1024 * 1024)
	}
	fmt.Printf("MMDB compiled: %s (%d entries, %.1f MB)\n", path, inserted, sizeMB)
	return nil
}

func networkKey(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, "/") {
		return ip
	}
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

func buildThreatMMDBEntry(networkKey string, rs []record.Record) mmdbtype.Map {
	threats := map[string]struct{}{}
	infra := map[string]struct{}{}
	classes := map[string]struct{}{}
	sources := map[string]struct{}{}
	dom := &rs[0]
	for i := range rs {
		r := &rs[i]
		// The dominant record contributes confidence and observation time. The
		// sets below keep the full source and label history for the prefix.
		if r.Confidence > dom.Confidence {
			dom = r
		}
		for _, v := range r.Threat {
			addSet(threats, v)
		}
		for _, v := range r.Infrastructure {
			addSet(infra, v)
		}
		for _, v := range r.Classification {
			addSet(classes, v)
		}
		addSet(sources, r.SourceName)
	}

	score := threatScore(threats, infra, classes)
	entry := mmdbtype.Map{
		"matched_prefix":    mmdbtype.String(networkKey),
		"threat":            stringSetSlice(threats),
		"infrastructure":    stringSetSlice(infra),
		"classification":    stringSetSlice(classes),
		"sources":           stringSetSlice(sources),
		"confidence":        mmdbtype.Uint16(uint16(dom.Confidence)),
		"score":             mmdbtype.Uint16(uint16(score)),
		"level":             mmdbtype.String(riskLevel(score)),
		"database_built_at": mmdbtype.String(time.Now().UTC().Format(time.RFC3339)),
	}
	if !dom.LastSeen.IsZero() {
		entry["observed_at"] = mmdbtype.String(dom.LastSeen.UTC().Format(time.RFC3339))
	}
	return entry
}

func addSet(set map[string]struct{}, v string) {
	v = strings.TrimSpace(v)
	if v != "" {
		set[v] = struct{}{}
	}
}

func stringSetSlice(set map[string]struct{}) mmdbtype.Slice {
	values := make([]string, 0, len(set))
	for v := range set {
		values = append(values, v)
	}
	sort.Strings(values)
	out := make([]mmdbtype.DataType, 0, len(values))
	for _, v := range values {
		out = append(out, mmdbtype.String(v))
	}
	return mmdbtype.Slice(out)
}

func threatScore(threats, infra, classes map[string]struct{}) int {
	score := len(threats)*15 + len(infra)*10 + len(classes)*6
	for _, strong := range []string{"malware_host_active", "compromised_or_hostile_host", "persistent_attacker", "prefix_cybercrime", "asn_high_risk", "c2_ioc", "phishing_or_scam"} {
		if _, ok := threats[strong]; ok {
			score += 25
		}
		if _, ok := infra[strong]; ok {
			score += 25
		}
		if _, ok := classes[strong]; ok {
			score += 25
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "high"
	case score >= 60:
		return "medium_high"
	case score >= 35:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

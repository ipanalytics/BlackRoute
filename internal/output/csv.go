// Package output writes threat records as CSV, JSON Lines, and MMDB.
package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"blackroute/internal/record"
)

var CSVHeader = []string{
	"ip", "source",
	"threat", "infrastructure", "classification",
	"confidence",
}

// WriteCSV writes records to path with the canonical header.
func WriteCSV(path string, records []record.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(CSVHeader); err != nil {
		return err
	}

	// Stable sort: primary by IP version (v4 first), then numeric IP order.
	// Approximate but easier on the eye than random insertion order.
	sortRecords(records)

	for _, r := range records {
		row := []string{
			r.IP,
			r.SourceName,
			strings.Join(r.Threat, "|"),
			strings.Join(r.Infrastructure, "|"),
			strings.Join(r.Classification, "|"),
			strconv.Itoa(r.Confidence),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	fmt.Printf("    ✓ wrote %s (%d rows)\n", path, len(records))
	return nil
}

func sortRecords(rs []record.Record) {
	sort.Slice(rs, func(i, j int) bool {
		ai := rs[i].IP
		aj := rs[j].IP
		// IPv4 first ('.' present), IPv6 second.
		isV4i := contains(ai, '.')
		isV4j := contains(aj, '.')
		if isV4i != isV4j {
			return isV4i
		}
		return ai < aj
	})
}

func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

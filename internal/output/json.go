package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"blackroute/internal/record"
)

// jsonRow is the on-disk JSON shape — strict subset of record.Record.
type jsonRow struct {
	IP             string   `json:"ip"`
	Source         string   `json:"source,omitempty"`
	Threat         []string `json:"threat,omitempty"`
	Infrastructure []string `json:"infrastructure,omitempty"`
	Confidence     int      `json:"confidence"`
}

func toJSONRow(r record.Record) jsonRow {
	return jsonRow{
		IP:             r.IP,
		Source:         r.SourceName,
		Threat:         r.Threat,
		Infrastructure: r.Infrastructure,
		Confidence:     r.Confidence,
	}
}

// WriteJSONL writes records to path as newline-delimited JSON.
func WriteJSONL(path string, records []record.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	sortRecords(records)

	w := bufio.NewWriterSize(f, 1<<20)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, r := range records {
		if err := enc.Encode(toJSONRow(r)); err != nil {
			return fmt.Errorf("encode %s: %w", r.IP, err)
		}
	}
	return w.Flush()
}

package pipeline

import "blackroute/internal/record"

func MergeRecords(in []record.Record) []record.Record {
	seen := make(map[string]int, len(in))
	out := make([]record.Record, 0, len(in))
	for _, r := range in {
		if r.IP == "" {
			continue
		}
		// The IP or prefix is the stable key. Multiple source hits collapse into
		// one record while preserving labels and the strongest confidence.
		if idx, ok := seen[r.IP]; ok {
			out[idx].MergeWith(r)
			continue
		}
		seen[r.IP] = len(out)
		out = append(out, r)
	}
	return out
}

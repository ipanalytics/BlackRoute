package record

import "time"

type SourceKind string

const (
	KindAggregator    SourceKind = "aggregator"
	KindCommunity     SourceKind = "community"
	KindCurated       SourceKind = "curated"
	KindAuthoritative SourceKind = "authoritative"
)

var DefaultConfidence = map[SourceKind]int{
	KindAggregator:    55,
	KindCommunity:     70,
	KindCurated:       85,
	KindAuthoritative: 95,
}

type Record struct {
	IP             string    `json:"ip"`
	SourceName     string    `json:"source,omitempty"`
	SourceURL      string    `json:"url,omitempty"`
	Threat         []string  `json:"threat,omitempty"`
	Infrastructure []string  `json:"infrastructure,omitempty"`
	Classification []string  `json:"classification,omitempty"`
	Confidence     int       `json:"confidence"`
	LastSeen       time.Time `json:"last_seen"`
}

func (r *Record) MergeWith(other Record) {
	if other.Confidence > r.Confidence {
		r.SourceURL = other.SourceURL
		r.SourceName = other.SourceName
		r.Confidence = other.Confidence
	}
	if r.SourceName == "" {
		r.SourceName = other.SourceName
	}
	r.Threat = mergeStringSets(r.Threat, other.Threat)
	r.Infrastructure = mergeStringSets(r.Infrastructure, other.Infrastructure)
	r.Classification = mergeStringSets(r.Classification, other.Classification)
	if other.LastSeen.After(r.LastSeen) {
		r.LastSeen = other.LastSeen
	}
}

func mergeStringSets(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range append(a, b...) {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

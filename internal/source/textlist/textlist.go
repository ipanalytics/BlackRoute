package textlist

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"blackroute/internal/domainx"
	"blackroute/internal/downloader"
	"blackroute/internal/record"
)

type Source struct {
	name           string
	urls           []string
	dl             *downloader.Client
	kind           record.SourceKind
	threat         []string
	infrastructure []string
}

type Config struct {
	Name           string
	URLs           []string
	Kind           record.SourceKind
	Threat         []string
	Infrastructure []string
}

func New(cfg Config, dl *downloader.Client) *Source {
	if cfg.Kind == "" {
		cfg.Kind = record.KindAggregator
	}
	return &Source{
		name:           cfg.Name,
		urls:           cfg.URLs,
		dl:             dl,
		kind:           cfg.Kind,
		threat:         append([]string(nil), cfg.Threat...),
		infrastructure: append([]string(nil), cfg.Infrastructure...),
	}
}

func (s *Source) Name() string            { return s.name }
func (s *Source) Kind() record.SourceKind { return s.kind }

func (s *Source) Fetch(ctx context.Context) ([]record.Record, error) {
	if len(s.urls) == 0 {
		return nil, errors.New("textlist: no URLs")
	}
	out := make([]record.Record, 0, 2048)
	now := time.Now().UTC()
	var lastErr error
	for _, u := range s.urls {
		body, err := s.dl.FetchBytes(ctx, u)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", u, err)
			continue
		}
		if len(body) == 0 {
			lastErr = fmt.Errorf("%s: empty body", u)
			continue
		}
		seen := make(map[string]struct{}, 1024)
		sc := bufio.NewScanner(strings.NewReader(string(body)))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := stripComment(strings.TrimSpace(sc.Text()))
			if line == "" {
				continue
			}
			// Feeds are evidence lists. Blackroute extracts public IPs and CIDRs;
			// hostname-only entries are ignored instead of being resolved.
			for _, tok := range extractIPTokens(line) {
				if strings.Contains(tok, "/") {
					asCIDR := domainx.NormalizePublicCIDR(tok)
					if asCIDR != "" {
						if _, dup := seen[asCIDR]; dup {
							continue
						}
						seen[asCIDR] = struct{}{}
						out = append(out, s.makeRecord(asCIDR, u, now))
					}
					continue
				}
				if norm, _ := domainx.NormalizePublicIP(tok); norm != "" {
					if _, dup := seen[norm]; dup {
						continue
					}
					seen[norm] = struct{}{}
					out = append(out, s.makeRecord(norm, u, now))
				}
			}
		}
	}
	if len(out) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("textlist: no IP data")
	}
	return out, nil
}

func stripComment(line string) string {
	if i := strings.Index(line, "#"); i != -1 {
		return strings.TrimSpace(line[:i])
	}
	return line
}

func extractIPTokens(line string) []string {
	// This tokenizer covers plain text, CSV, JSON-ish arrays, and netset files
	// without assigning meaning to unrelated fields on the same line.
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ';' || r == ':' || r == '\t' || r == ' ' || r == '[' || r == ']' || r == '{' || r == '}' || r == '"' || r == '\''
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, "`()")
		if f == "" || f == "0.0.0.0" || f == "127.0.0.1" {
			continue
		}
		if strings.Contains(f, "/") {
			if domainx.NormalizePublicCIDR(f) != "" {
				out = append(out, f)
			}
			continue
		}
		if _, v := domainx.NormalizePublicIP(f); v != 0 {
			out = append(out, f)
		}
	}
	return out
}

func (s *Source) makeRecord(ip, sourceURL string, ts time.Time) record.Record {
	return record.Record{
		IP:             ip,
		SourceName:     s.name,
		SourceURL:      sourceURL,
		Confidence:     record.DefaultConfidence[s.kind],
		LastSeen:       ts,
		Threat:         append([]string(nil), s.threat...),
		Infrastructure: append([]string(nil), s.infrastructure...),
	}
}

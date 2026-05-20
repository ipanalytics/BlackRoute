// Package source defines the DataSource interface used by threat feeds.
//
//	type DataSource interface {
//	    Name() string
//	    Kind() record.SourceKind
//	    Fetch(ctx context.Context) ([]record.Record, error)
//	}
//
// The pipeline iterates over a slice of DataSource, calls Fetch on each, then
// merges records and writes outputs.
package source

import (
	"context"

	"blackroute/internal/record"
)

// DataSource is the contract every input must satisfy.
//
// Fetch should be safe to call once per pipeline run and must respect ctx
// cancellation for downloads.
type DataSource interface {
	// Name returns the canonical key for this feed.
	Name() string

	// Kind identifies the trust level so the pipeline can assign default
	// confidence and apply rate-limit / scheduling policies.
	Kind() record.SourceKind

	// Fetch performs all I/O and returns the harvested records.
	Fetch(ctx context.Context) ([]record.Record, error)
}

// Registry holds all enabled sources for a single pipeline run.
//
// Sources can be added programmatically (in main.go) or via the YAML config
// loader in internal/config.
type Registry struct {
	sources []DataSource
}

func NewRegistry() *Registry {
	return &Registry{sources: make([]DataSource, 0, 64)}
}

// Add registers a single source. Duplicate names overwrite — last wins.
func (r *Registry) Add(s DataSource) {
	for i, existing := range r.sources {
		if existing.Name() == s.Name() {
			r.sources[i] = s
			return
		}
	}
	r.sources = append(r.sources, s)
}

// All returns the registered sources in registration order.
func (r *Registry) All() []DataSource { return r.sources }

// Filter returns sources whose Name() matches one of names. If names is empty,
// all sources are returned. Used by --only flag in main.
func (r *Registry) Filter(names []string) []DataSource {
	if len(names) == 0 {
		return r.sources
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := make([]DataSource, 0, len(names))
	for _, s := range r.sources {
		if want[s.Name()] {
			out = append(out, s)
		}
	}
	return out
}

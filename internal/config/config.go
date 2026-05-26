package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"blackroute/internal/downloader"
	"blackroute/internal/record"
	"blackroute/internal/source"
	"blackroute/internal/source/textlist"
)

type FeedsFile struct {
	Feeds []FeedDecl `yaml:"feeds"`
}

type FeedDecl struct {
	Kind           string   `yaml:"kind"`
	Name           string   `yaml:"name"`
	DisplayName    string   `yaml:"display_name"`
	Disabled       bool     `yaml:"disabled,omitempty"`
	URLs           []string `yaml:"urls,omitempty"`
	Trust          string   `yaml:"trust,omitempty"`
	Threat         []string `yaml:"threat,omitempty"`
	Infrastructure []string `yaml:"infrastructure,omitempty"`
	Classification []string `yaml:"classification,omitempty"`
}

type Deps struct {
	Downloader *downloader.Client
}

func LoadFeeds(path string, deps Deps) ([]source.DataSource, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f FeedsFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]source.DataSource, 0, len(f.Feeds))
	for i, p := range f.Feeds {
		if p.Disabled {
			continue
		}
		ds, err := buildFeed(p, deps)
		if err != nil {
			return nil, fmt.Errorf("feed[%d] %q: %w", i, p.Name, err)
		}
		out = append(out, ds)
	}
	return out, nil
}

func buildFeed(p FeedDecl, deps Deps) (source.DataSource, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.Kind == "" {
		p.Kind = "textlist"
	}
	switch p.Kind {
	case "textlist":
		kind := sourceKind(p.Trust)
		return textlist.New(textlist.Config{
			Name:           p.Name,
			URLs:           p.URLs,
			Kind:           kind,
			Threat:         p.Threat,
			Infrastructure: p.Infrastructure,
			Classification: p.Classification,
		}, deps.Downloader), nil
	default:
		return nil, fmt.Errorf("unknown kind %q", p.Kind)
	}
}

func sourceKind(trust string) record.SourceKind {
	switch trust {
	case "authoritative":
		return record.KindAuthoritative
	case "curated":
		return record.KindCurated
	case "community":
		return record.KindCommunity
	default:
		return record.KindAggregator
	}
}

// Package pipeline runs a complete Blackroute feed build.
package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"blackroute/internal/output"
	"blackroute/internal/record"
	"blackroute/internal/source"
)

type Options struct {
	Registry         *source.Registry
	FetchConcurrency int
	OutputDir        string
	SkipMMDB         bool
}

type Result struct {
	TotalRecords int
	BySource     map[string]int
	Errors       map[string]error
	OutputFiles  []string
	Elapsed      time.Duration
}

func Run(ctx context.Context, opts Options) (*Result, error) {
	start := time.Now()
	res := &Result{
		BySource: make(map[string]int),
		Errors:   make(map[string]error),
	}
	if opts.Registry == nil {
		return nil, fmt.Errorf("pipeline.Run: nil Registry")
	}

	sources := opts.Registry.All()
	allRecords := make([]record.Record, 0, 65536)
	var allMu sync.Mutex
	appendRecords := func(srcName string, rs []record.Record, err error) {
		allMu.Lock()
		defer allMu.Unlock()
		for i := range rs {
			if rs[i].SourceName == "" {
				rs[i].SourceName = srcName
			}
			res.BySource[rs[i].SourceName]++
		}
		if err != nil {
			res.Errors[srcName] = err
		}
		allRecords = append(allRecords, rs...)
	}

	conc := opts.FetchConcurrency
	if conc <= 0 {
		conc = 4
	}
	fmt.Printf("Fetching %d feed(s) with concurrency=%d...\n", len(sources), conc)
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, s := range sources {
		s := s
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rs, err := s.Fetch(ctx)
			if err != nil {
				fmt.Printf("  x %-32s %v\n", s.Name(), err)
			} else {
				fmt.Printf("  ok %-31s %d records\n", s.Name(), len(rs))
			}
			appendRecords(s.Name(), rs, err)
		}()
	}
	wg.Wait()

	fmt.Printf("Merging %d raw records...\n", len(allRecords))
	merged := MergeRecords(allRecords)
	fmt.Printf("  -> %d unique IP/prefix records\n", len(merged))

	res.TotalRecords = len(merged)

	if opts.OutputDir == "" {
		opts.OutputDir = "release"
	}
	if err := output.WriteRunStats(filepath.Join(opts.OutputDir, "run_stats.json"), merged); err != nil {
		fmt.Printf("  stats skipped: %v\n", err)
	}
	if err := writeAll(opts, merged, res); err != nil {
		return res, err
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func writeAll(opts Options, recs []record.Record, res *Result) error {
	csvPath := filepath.Join(opts.OutputDir, "blackroute.csv")
	jsonlPath := filepath.Join(opts.OutputDir, "blackroute.jsonl")
	mmdbPath := filepath.Join(opts.OutputDir, "blackroute.mmdb")

	fmt.Printf("Writing %d records -> %s\n", len(recs), opts.OutputDir)
	if err := output.WriteCSV(csvPath, recs); err != nil {
		return fmt.Errorf("write csv: %w", err)
	}
	res.OutputFiles = append(res.OutputFiles, csvPath)
	if err := output.WriteJSONL(jsonlPath, recs); err != nil {
		return fmt.Errorf("write jsonl: %w", err)
	}
	res.OutputFiles = append(res.OutputFiles, jsonlPath)
	if !opts.SkipMMDB {
		if err := output.WriteThreatMMDB(mmdbPath, recs); err != nil {
			return fmt.Errorf("write mmdb: %w", err)
		}
		res.OutputFiles = append(res.OutputFiles, mmdbPath)
	}
	return nil
}

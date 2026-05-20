package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"blackroute/internal/config"
	"blackroute/internal/downloader"
	"blackroute/internal/pipeline"
	"blackroute/internal/source"
)

func main() {
	var (
		feedsPath = flag.String("feeds", "configs/feeds.yaml", "path to feed YAML")
		outputDir = flag.String("output", "release", "directory for blackroute.csv / blackroute.jsonl / blackroute.mmdb")
		only      = flag.String("only", "", "comma-separated feed names to include")
		skipMMDB  = flag.Bool("skip-mmdb", false, "skip MMDB compile step")
	)
	flag.Parse()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		die("mkdir output: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nsignal received, cancelling...")
		cancel()
	}()

	dlClient := downloader.New()
	registry := source.NewRegistry()
	feeds, err := config.LoadFeeds(*feedsPath, config.Deps{Downloader: dlClient})
	if err != nil {
		die("load feeds: %v", err)
	}
	fmt.Printf("Loaded %d enabled feed(s) from %s\n", len(feeds), *feedsPath)
	for _, s := range feeds {
		registry.Add(s)
	}
	if *only != "" {
		filtered := registry.Filter(strings.Split(*only, ","))
		fmt.Printf("--only filter: %d -> %d feed(s)\n", len(registry.All()), len(filtered))
		registry = source.NewRegistry()
		for _, s := range filtered {
			registry.Add(s)
		}
	}
	if len(registry.All()) == 0 {
		die("no feeds to run; check %s and --only", *feedsPath)
	}

	res, err := pipeline.Run(ctx, pipeline.Options{
		Registry:         registry,
		FetchConcurrency: 4,
		OutputDir:        *outputDir,
		SkipMMDB:         *skipMMDB,
	})
	if err != nil {
		die("pipeline: %v", err)
	}

	fmt.Println()
	fmt.Println("Done")
	fmt.Printf("  total records: %d\n", res.TotalRecords)
	fmt.Println("  outputs:")
	for _, p := range res.OutputFiles {
		abs, _ := filepath.Abs(p)
		fmt.Printf("    %s\n", abs)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

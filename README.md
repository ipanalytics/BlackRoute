# Blackroute

Blackroute builds a local IP reputation database from public abuse, malware, bot, bogon, and high-risk infrastructure feeds. The primary artifact is `blackroute.mmdb`, a MaxMind-compatible database that can be used in gateways, proxies, fraud checks, SIEM pipelines, and internal enrichment jobs.

Blackroute does not resolve hostnames, query PTR records, crawl DNS, fingerprint networks, or scan anything. It only downloads configured feeds, extracts public IP addresses and CIDR prefixes, attaches labels, merges duplicates, and writes deterministic output files.

![Blackroute Banner](https://raw.githubusercontent.com/ipanalytics/blackroute/main/site/banner.png)

## Why Blackroute

- Transparent source mapping: every record keeps the feed name, source URL, confidence, threat labels, and infrastructure labels.
- Cron-friendly operation: one binary, one YAML file, stable outputs, no admin panel.
- Low runtime cost: compile once, then perform fast MMDB lookups in your own stack.
- Practical alternative or supplement to paid reputation databases when you need local control, auditability, and repeatable builds.
- Conservative parsing: private, local, multicast, unspecified, and overly broad ranges are ignored before output.

## Outputs

| File | Purpose |
| --- | --- |
| `release/blackroute.mmdb` | MaxMind DB for runtime IP and prefix lookups |
| `release/blackroute.csv` | Flat table for review, diffing, and import jobs |
| `release/blackroute.jsonl` | Line-delimited records for pipelines |
| `release/run_stats.json` | Build summary and label counts |

MMDB records use this shape:

```json
{
  "matched_prefix": "203.0.113.10/32",
  "threat": ["recent_attack_any", "recent_attack_ssh"],
  "infrastructure": ["bogon"],
  "sources": ["blocklist_de_ssh"],
  "confidence": 70,
  "score": 55,
  "level": "medium",
  "observed_at": "2026-05-20T12:00:00Z",
  "database_built_at": "2026-05-20T12:05:00Z"
}
```

## Quick Start

```bash
bash scripts/setup-server.sh
./run.sh
```

Build without MMDB when you only need CSV and JSONL:

```bash
./run.sh --skip-mmdb
```

Run only selected feeds:

```bash
./run.sh --only=blocklist_de_ssh,emergingthreats_compromised
```

Use a custom feed file or output directory:

```bash
./run.sh --feeds=configs/feeds.yaml --output=release
```

Build the binary directly:

```bash
go build -o ./bin/blackroute ./cmd/collector
./bin/blackroute --feeds=configs/feeds.yaml --output=release
```

Run tests:

```bash
go test ./...
```

## Cron

Use the wrapper when running from cron. It builds the binary if needed, prevents overlapping runs, and keeps Go build caches outside the repository by default.

```cron
17 * * * * cd /opt/blackroute && APP_DIR=/opt/blackroute scripts/run-cron.sh >> var/log/cron.log 2>&1
```

Manual cron-style run:

```bash
APP_DIR=/opt/blackroute /opt/blackroute/scripts/run-cron.sh
```

Optional cache override:

```bash
BLACKROUTE_CACHE_DIR=/var/cache/blackroute/go ./run.sh
```

## Feed Configuration

Feeds live in `configs/feeds.yaml`.

```yaml
feeds:
  - kind: textlist
    name: blocklist_de_ssh
    display_name: blocklist.de SSH
    trust: community
    threat: [recent_attack_any, recent_attack_ssh]
    urls:
      - https://lists.blocklist.de/lists/ssh.txt
```

Supported fields:

| Field | Meaning |
| --- | --- |
| `kind` | Currently `textlist`; extracts public IPs and CIDRs from text, CSV, JSON-ish, and netset-style lines |
| `name` | Stable source identifier written to output records |
| `display_name` | Human-readable source name for operators |
| `disabled` | Set to `true` to keep a feed configured but inactive |
| `trust` | `aggregator`, `community`, `curated`, or `authoritative`; controls default confidence |
| `threat` | Labels for hostile behavior or active reputation |
| `infrastructure` | Labels for network context such as bogons, anonymous infrastructure, or high-risk prefixes |
| `urls` | One or more feed URLs |

## Included Sources

The default configuration includes:

- blocklist.de: SSH, mail, web, IMAP, FTP, SIP, bots, and strong IP lists.
- Emerging Threats: compromised and hostile hosts.
- CINSscore: multi-sensor high-risk addresses.
- FireHOL: anonymous infrastructure and 1-day abuser aggregation.
- Spamhaus: DROP and ASNDROP-derived high-risk infrastructure.
- Team Cymru: IPv4 and IPv6 full bogon prefixes.
- abuse.ch Feodo Tracker: active botnet C2 IPs.
- SANS ISC DShield, GreenSnow, and IPsum for community risk signals.

Commercial feeds and API-key feeds are intentionally not bundled. Add them as private entries in `configs/feeds.yaml` when your license allows local redistribution or internal use.

## Labels

Threat labels describe behavior:

```json
[
  "recent_attack_any",
  "recent_attack_ssh",
  "recent_attack_mail",
  "recent_attack_web",
  "recent_attack_imap",
  "recent_attack_ftp",
  "recent_attack_sip",
  "recent_badbot_or_regbot",
  "persistent_attacker",
  "malware_host_active",
  "compromised_or_hostile_host",
  "community_high_risk",
  "multi_sensor_high_risk",
  "aggregate_abuser_1d"
]
```

Infrastructure labels describe network context:

```json
[
  "aggregate_anonymizer",
  "bogon",
  "prefix_cybercrime",
  "asn_high_risk"
]
```

## Project Layout

```text
cmd/collector/              CLI entrypoint
configs/                    Feed configuration
internal/config/            YAML loader
internal/domainx/           IP and CIDR normalization
internal/downloader/        HTTP fetch client
internal/source/textlist/   Feed parser
internal/pipeline/          Fetch, merge, and write flow
internal/output/            CSV, JSONL, stats, and MMDB writers
internal/record/            Shared record model
scripts/                    Setup and cron wrappers
site/                       Static GitHub Pages site
```

## Notes

Blackroute is a reputation compiler, not a verdict engine. Treat labels as signals, combine them with your own allowlists and policy, and review high-impact blocking decisions before enforcing them globally.

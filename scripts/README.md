# Scripts

## `setup-server.sh`

Installs the basic system dependencies on apt or dnf based Linux hosts and downloads Go modules.

```bash
bash scripts/setup-server.sh
```

## `run-cron.sh`

Runs Blackroute with a lock file so cron jobs do not overlap.

```bash
APP_DIR=/opt/blackroute /opt/blackroute/scripts/run-cron.sh
```

Example crontab:

```cron
17 * * * * cd /opt/blackroute && APP_DIR=/opt/blackroute scripts/run-cron.sh >> var/log/cron.log 2>&1
```

## `check-feeds.sh`

Checks HTTP feed availability and reports stale `Last-Modified` headers.

```bash
scripts/check-feeds.sh
MAX_FEED_AGE_HOURS=72 scripts/check-feeds.sh configs/feeds.yaml
```

## `build-threatfox-feed.sh`

Generates `local/feeds/threatfox_ips.txt` directly from the public ThreatFox ZIP/CSV export. The generated file is read before the remote abuse.ch export.

```bash
scripts/build-threatfox-feed.sh
```

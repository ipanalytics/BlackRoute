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

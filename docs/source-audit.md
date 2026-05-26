# Source Audit

This file records upstream handling for active Blackroute feeds that were reviewed through `elliotwutingfeng` scraper code. Direct upstream sources are used when they are public and compatible with the IP/CIDR pipeline. Mirrors remain only when the mirror itself is the generated IP artifact or the upstream requires a separate keyed/session-based generator.

| Feed | Source used by Blackroute | Upstream access | Update cadence observed upstream/mirror | Status |
| --- | --- | --- | --- | --- |
| `threatfox_ioc_ips` | `https://threatfox.abuse.ch/export/csv/ip-port/full` | Public ZIP/CSV export, no key for this export. | Hourly mirror cadence. | Direct upstream. |
| `usom_blocklist_ips` | `https://www.usom.gov.tr/url-list.txt` | Public text feed. Monitor because USOM announced migration away from plain `.txt` distribution. | Daily mirror cadence. | Direct upstream. |
| `inversion_cloud_ips` | `https://raw.githubusercontent.com/elliotwutingfeng/Inversion-CloudIPs/main/ips.txt` | Generated IP artifact derived from Inversion DNSBL hostnames. | Hourly mirror cadence. | Mirror retained. |
| `inversion_dnsbl_google_ipv4` | `https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_ipv4.txt` | Original generation requires Safe Browsing API access and the Inversion DNSBL generator. | Generator cadence is external to the artifact repo. | Mirror retained. |
| `ukrainian_ema_blocklist_ips` | `https://www.ema.com.ua/wp-json/api/blacklist-query?count=1000000` | Public JSON endpoint, no key in scraper. | Daily mirror cadence. | Direct upstream. |
| `acma_blocked_gambling_ips` | `https://backend.acma.gov.au/gmbl/api/Domain` | Public JSON endpoint, no key in scraper. | Daily mirror cadence. | Direct upstream. |
| `global_anti_scam_ips` | `https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-ips.txt` | Original Wix API requires a live browser session token. No static public IP feed was found. | Daily mirror cadence. | Mirror retained. |
| `alienvault_reputation_generic` | `https://reputation.alienvault.com/reputation.generic` | Public reputation feed used directly by Maltrail. | Monitor by HTTP freshness. | Direct upstream. |
| `dataplane_attack_feeds` | `https://dataplane.org/*.txt` category feeds | Public pipe-delimited attack feeds used directly by Maltrail. | Monitor by HTTP freshness. | Direct upstream. |
| `ziyadnz_threat_intel_hourly_ipv4` | `https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt` | Hourly aggregate IP output. Includes API-key-backed upstreams such as AbuseIPDB and OTX, so Blackroute treats it as an aggregate signal. | Hourly project cadence. | Aggregate retained. |

## Operational Notes

- Keep retained mirrors under `scripts/check-feeds.sh` monitoring.
- Prefer local generated files under `local/feeds/` for keyed or session-backed sources.

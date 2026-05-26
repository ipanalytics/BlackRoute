# Feed Configuration

`feeds.yaml` is the source catalog for Blackroute. Each enabled entry is downloaded, parsed for public IP addresses and CIDR prefixes, labeled, and merged into the release files.

```yaml
feeds:
  - kind: textlist
    name: blocklist_de_ssh
    display_name: blocklist.de SSH
    trust: community
    threat: [recent_attack_any]
    urls:
      - https://lists.blocklist.de/lists/ssh.txt
```

Use `disabled: true` to keep a source in the catalog without running it. Use `infrastructure` for network context such as bogons or high-risk prefixes; use `threat` for hostile behavior or active reputation; use `classification` for source category context such as scam, policy, C2, DNSBL, or national CERT signals.

Put direct upstream URLs first and mirrors second. Local files are also supported, which lets operators generate API-backed feeds under `local/feeds/` and keep public mirrors as fallbacks.

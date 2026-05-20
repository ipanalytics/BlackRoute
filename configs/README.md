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

Use `disabled: true` to keep a source in the catalog without running it. Use `infrastructure` for network context such as bogons or high-risk prefixes; use `threat` for hostile behavior or active reputation.

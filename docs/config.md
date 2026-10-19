# Configuration

Three sources set the configuration. The order is fixed.
Command flags win. Environment is next. The TOML file is next. Built-in values are last.

## Sources

- Flags use two dashes, for example the listen address flag.
- Environment entries start with DUMBDNS_.
- The file path comes from the config flag. The file uses TOML format.

## Important Flags

- dns-listening-address — UDP and TCP listen address.
- llm-endpoint — model server address.
- llm-backend — tgi or openai. For openai, include /v1 in the address.
- auth-token — token for raw prompts and all writes.
- doh-bearer — token for encrypted transports.
- allowlist — client addresses that may connect. Empty means all.
- rate-limit — requests per second per client. Zero means no limit.
- tls-cert and tls-key — certificate files. Empty means self-signed.
- dnssec-key — private key file for answer signing. Empty means unsigned.
- deny-patterns — block expressions, comma separated.
- max-qname-bytes — longest accepted query name.
- kill-file — stop file. When present, model paths refuse.
- audit-log — log file path. Empty means no log.
- metrics-address — metrics address. Empty means off.
- cache-size — memory cache entries. Zero means off.

References

- TOML format — https://toml.io

# dumbdns-rs
LLM client in a DNS server (Rust rebuild of Shell-Company/dumbdns).
TXT queries -> TGI/OpenAI-compat LLM -> TXT answers (255B-chunked).

## Credits
Inspired by [Shell-Company/dumbdns](https://github.com/Shell-Company/dumbdns)
(Go + `miekg/dns` + TGI `/generate`). This is an independent Rust
reimplementation (hickory-server), not a fork (see `docs/` for transports, namespaces, and security).
## Transports
UDP+TCP always. Opt-in: `--dot-address 127.0.0.1:853` (DoT),
`--doh-address 127.0.0.1:8443` (DoH), `--doq-address 127.0.0.1:853` (DoQ).
TLS via `--tls-cert/--tls-key` PEM or ephemeral self-signed (`--dns-hostname`).
## DNSSEC
`--dnssec-key <ed25519-pkcs8-pem>` signs TXT RRsets (RRSIG on DO-bit queries)
and serves DNSKEY at the zone apex.
Generate: `openssl genpkey -algorithm ed25519 -out dnssec.pem`
## Namespaces (`{id}[._feature[.args]].{zone}`)
- `{key}._kv.dumb.` getter/setter KV (UPDATE to write, TXT to read)
- `{task}._c2.dumb.` same mechanism, C2 tasking/output namespace
- `{session}._mem.dumb.` memory write; recalled on `{session}.dumb.` reads
- `{session}._page.{N}.dumb.` paging; `{session}._part.{N}.{chunk}.dumb.` fragments
- Beads: dotted ids nest (`n2.n1.proj9`), DNS-reversed (specific first);
  a parent read pulls child-bead facts, general first
- Underscore marks infrastructure (IETF style: `_dmarc`, SRV records).
  Data labels never collide with features.
- `{id}._llm.{words}.dumb.` explicit ask: short identity, text after the feature
- Bare `{id}.dumb.` continues/flushes; brand-new ids answer empty with no model call
- Anything else is a raw LLM prompt (token-gated if configured)
## Sessions / RAG / smuggling
`session.dumb.` multi-turn history (sqlite), `--rag-corpus` TF-IDF inject,
`--smuggle-a/--smuggle-aaaa/--smuggle-cname` encode LLM bytes as records.
## Auth / limits
`--allowlist`, `--auth-token` (first-label), per-IP `--rate-limit` (governor token-bucket).
`--doh-bearer` token required as first QNAME label on DoT/DoH/DoQ.
## Config
Flags > env (`DUMBDNS_*`) > `--config` TOML file > defaults. Example TOML keys:
`llm_endpoint`, `rate_limit`, `allowlist`, `dot_address`, `dnssec_key`, ...
## Metrics
`--metrics-address 127.0.0.1:9090` serves Prometheus text at `GET /metrics`.
## Use
cargo build --release
./target/release/dumbdns --dns-listening-address 127.0.0.1:5353 --llm-endpoint http://localhost:8080
dig @127.0.0.1 -p 5353 txt "hello world" +short
./target/release/dumbdns --help
## Walkthrough (verified 2026-10-19 against release binary + stub TGI)
1. TXT prompt -> LLM: `dig @127.0.0.1 -p 5353 txt "what is dns"` returns the
   model reply as chunked TXT (`AA`, NOERROR).
2. Setter (needs `--auth-token s3cr3t`): UPDATE `greeting.kv.dumb.` TXT
   with zone query `s3cr3t.dumb.` -> NOERROR (stored); without token -> REFUSED.
3. Getter: TXT `greeting.kv.dumb.` returns the stored value, no LLM call.
4. Non-TXT (e.g. A) without `--smuggle-a` -> empty NOERROR.
## Verify
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test

# Security

DNS is clear text on UDP and TCP. DNS names appear in logs on every hop.
Do not send secrets in queries. This tool is dual-use. Run it only on networks you own or approve.

## Access Control

- The allowlist names client addresses. Empty means the world may connect. Do not expose it openly.
- The auth token gates raw prompts and all writes. It travels in the query name. Treat it as a key, not a secret, on clear transports.
- The bearer gates encrypted transports. TLS still shields it in transit.
- Session, KV, and C2 reads need no token. Their names are the capability. Use names that others cannot guess.

## Abuse Controls

- Rate limits bound each client. Bursts have the same bound.
- Deny patterns block exfil shapes in prompts and values. Matching ignores case because DNS folds case.
- Query names have a length cap. Replies have a size cap.
- The kill file stops all model paths at once. Key and empty answers still serve.
- The audit log records each query as one JSON line.

## Threat Model

- UDP sender addresses are easy to fake. Allowlist and rate limits are weak on UDP alone.
- Each query can spend model budget. The cache, caps, and breaker bound that spend.
- Stored keys and session names are visible to any reader. Guessable names leak.
- TSIG is not available. The DNS library drops raw bytes before the handler, so no server check is possible. The controls above are the mitigation.

## Operator Rules

- Bind to local or private addresses. Filter the port at the firewall.
- Use certificate files for DoT, DoH, and DoQ.
- Generate the DNSSEC key offline and guard the file.
- Rotate tokens when staff changes. Clear sessions by restart.

References

- RFC 8945 — TSIG background — https://www.rfc-editor.org/rfc/rfc8945
- OWASP LLM Top 10 — https://genai.owasp.org

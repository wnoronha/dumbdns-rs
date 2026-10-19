# Transports

The same handler serves all transports. UDP and TCP are always on.

## Transports

- UDP and TCP share one address. This is the default.
- DoT uses TLS on its own address.
- DoH uses HTTPS on its own address. Queries use POST with the DNS message type.
- DoQ uses QUIC on its own address. Only the bind has a test.

## TLS Identity

- Certificate files give the most trust. Use them in production.
- Without files, the server makes a short-lived self-signed certificate.
- Clients must accept or pin that certificate. Otherwise the handshake fails.
- DoH clients must use HTTP/2 with prior knowledge.

## DNSSEC

- A key file turns signing on.
- TXT answers carry a signature when the query sets the DO bit.
- The zone apex serves the public key on DNSKEY queries.

## Size Limits

- On UDP, the server honors the client EDNS limit.
- Oversize answers return the TC flag with no records. The client retries on TCP.
- Without EDNS, the server sends the full answer. This keeps old clients working.

References

- RFC 1035 — DNS base standard — https://www.rfc-editor.org/rfc/rfc1035
- RFC 8484 — DNS over HTTPS — https://www.rfc-editor.org/rfc/rfc8484
- RFC 7858 — DNS over TLS — https://www.rfc-editor.org/rfc/rfc7858
- RFC 9250 — DNS over QUIC — https://www.rfc-editor.org/rfc/rfc9250
- RFC 4035 — DNSSEC — https://www.rfc-editor.org/rfc/rfc4035
- RFC 6891 — EDNS — https://www.rfc-editor.org/rfc/rfc6891

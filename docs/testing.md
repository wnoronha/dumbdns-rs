# Testing

Three commands gate every change. All three must pass.

## Gate

- Format check keeps style fixed.
- Clippy with denied warnings keeps the code clean.
- The test run keeps behavior fixed.

## Test Layout

- Unit tests sit with the code. They cover parsing, chunking, storage, and scoring.
- Blackbox tests start the real server on local ports. They use scripted DNS messages and a stub model.
- Each server dies with its test. A guard kills orphans even on failure.
- UDP needs loopback access. Some sandboxes block odd ports. The suite uses the low test range.

References

- Hickory DNS project — https://github.com/hickory-dns/hickory-dns

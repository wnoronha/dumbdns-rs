# Getting Started

Start the server with a model address. Then ask it through DNS.
Ask with id dot _llm dot words. The id stays short for history and pages.
A bare id continues the session. A new one answers empty and spends nothing.
The examples use dig and nsupdate. Any DNS client works.

## 1. First Question

Start the server on a local port. Ask a TXT question.
The answer is model text in one or more TXT strings.

## 2. Flags Over DNS

Store a flag with an UPDATE. Name it key dot kv dot zone.
Set the auth token flag first. Writes without a token refuse.
Read the flag back with a TXT query. No model call happens.

## 3. Sessions and Memory

Ask under a session name to keep turns together.
Store a fact with an UPDATE to session dot mem dot zone.
Later reads of that session include the fact in the prompt.
Dotted names nest: child beads join parent reads, general first.

## 4. Long Answers

Long replies cut at the reply limit. The cut marks itself.
Read the full text page by page with session dot more dot number.
Each page holds one chunk of the stored reply.

## 5. Split Prompts

Split a long prompt into labeled parts ahead of the session name.
Each part answers ACK and stores. The plain session query
joins the parts in order and asks the model once.

## 6. Private Access

Serve DoT or DoH on their own addresses for encrypted clients.
Use certificate files in production. The bearer token gates
encrypted transports. Plain transports need firewall plus token.

## 7. Grounded Answers

Point the corpus flag at a text file, one document per line.
Matching documents join the prompt as context.
The model then answers from your text, not from memory alone.

## Useful Commands

dig txt — ask a question.
nsupdate with an update add line — store a value.
dig txt on a kv name — read it back.
curl on the metrics address with the metrics path — see counters.

References

- dig manual — https://man7.org/linux/man-pages/man1/dig.1.html
- nsupdate manual — https://man7.org/linux/man-pages/man1/nsupdate.1.html

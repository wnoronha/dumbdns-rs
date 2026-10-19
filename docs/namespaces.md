# Namespaces

Every setter follows one rule. The form is id, then feature, then zone.

## Names

- A key with kv stores a value. Read it back with a TXT query.
- A task with c2 does the same in the C2 area. Use it for two-way tasking.
- A session with mem stores a memory fact for that session.
- A session name alone continues the session. Stored memory joins the prompt.
- A bare new session answers empty. No text means no model call.
- An id with _llm asks with words after it. Identity stays short.
- Session dot more dot number reads one page of the last long answer.

## Blind Drop

The server stores bytes. It cannot read them. Keep it that way.
Encrypt before you store. The recipient decrypts after reading.
No server flag exists for this. None is needed.

- Seal offline with an age recipient key. Store the cipher text as a value.
- Hash offline for checks. Store the hex digest as a value.
- Readers compare or decrypt on their own machines.
- A stolen database holds noise. Sniffed traffic holds noise, on encrypted transports.

## Writes

- Writes use the UPDATE opcode.
- Writes need a token. No token means all writes refuse. This is the safe default.
- Writes also need an encrypted transport or a local sender.
- A blocked value refuses the whole update. Nothing is stored first.

## Memory Beads

- Session names may have dots. Example: n2.n1.proj9.
- Names read right to left, as DNS requires. The most exact label is first.
- A read pulls facts from the session and from all child beads.
- General facts come first. At most five facts join the prompt.

## Fragments

- Long prompts split into labeled parts. Each part gets an ACK. No model call happens yet.
- The plain session query joins the parts in order and asks the model once.

References

- RFC 2136 — DNS UPDATE — https://www.rfc-editor.org/rfc/rfc2136

# Language Model Back Ends

Two back ends exist. The default speaks the TGI generate protocol.
The openai back end speaks the OpenAI chat protocol through the async-openai crate.

## Back Ends

- Stateless prompts use TGI.
- Stateful sessions use OpenAI chat when selected. The full turn history goes with each call.
- Timeouts bound every call. Slow calls fail closed with an empty answer.

## RAG

- A text file holds one document per line.
- Retrieval uses TF-IDF cosine scoring. It is offline and needs no downloads.
- The top three documents join the system prompt as context.
- Neural embeddings are future work. They need a model download.

## Limits

- Histories keep at most forty entries.
- Replies cut at the reply limit on a character edge. The cut marks itself.
- Full replies stay cached per session for paging.
- Fragments buffer at most thirty-two parts per session.

## Breaker

- Repeated model failures open the circuit.
- An open circuit skips model calls until the cooldown ends.
- Counters show errors and open events.

References

- async-openai crate — https://docs.rs/async-openai
- TGI project — https://github.com/huggingface/text-generation-inference
- OpenAI API reference — https://platform.openai.com/docs/api-reference

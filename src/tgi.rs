use serde::Serialize;
use std::time::Duration;

/// Build the TGI `/generate` request body (mirrors Go map marshal).
#[derive(Debug, Serialize)]
pub struct TgiParameters {
    pub max_new_tokens: u32,
    pub temperature: f32,
    pub top_k: u32,
    pub top_p: f32,
    pub stop: Vec<String>,
    pub seed: u64,
}

#[derive(Debug, Serialize)]
pub struct TgiRequest {
    pub inputs: String,
    pub parameters: TgiParameters,
}

pub fn build_inputs(system_prompt: &str, query_as_prompt: &str) -> String {
    format!("<|system|>{system_prompt}<|user|>{query_as_prompt}")
}

/// Go: `strings.ReplaceAll(query, ".", " ") + "</s>"`.
pub fn query_to_prompt(query_fqdn: &str) -> String {
    format!("{}</s>", query_fqdn.replace('.', " "))
}

pub fn resolve_seed(configured: u64) -> u64 {
    if configured != 0 {
        configured
    } else {
        rand::random::<u64>() % 1000
    }
}

/// POST {endpoint}/generate — returns generated_text. Errors are propagated
/// (Go deref'd nil here; we return Err and the DNS layer answers empty/SERVFAIL).
pub async fn query_tgi(
    endpoint: &str,
    req: &TgiRequest,
    timeout: Duration,
) -> anyhow::Result<String> {
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let url = format!("{}/generate", endpoint.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Dumb DNS (rust)")
        .json(req)
        .send()
        .await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    if !status.is_success() {
        anyhow::bail!("LLM endpoint {status}: {}", body);
    }
    body.get("generated_text")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("missing generated_text: {body}"))
}

#[allow(dead_code)]
/// OpenAI-compatible chat backend via the `async-openai` crate (not hand-rolled).
///
/// Works against any OpenAI-compatible base URL (vLLM, TGI chat, OpenRouter…).
/// `api_key` may be empty for local endpoints.
pub async fn query_chat(
    endpoint: &str,
    model: &str,
    api_key: &str,
    messages: &[(String, String)],
    max_tokens: u32,
    timeout: Duration,
) -> anyhow::Result<String> {
    use async_openai::{
        config::OpenAIConfig,
        types::chat::{
            ChatCompletionRequestAssistantMessageArgs, ChatCompletionRequestMessage,
            ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs,
            CreateChatCompletionRequestArgs,
        },
        Client,
    };
    let config = OpenAIConfig::new()
        .with_api_base(endpoint.trim_end_matches('/'))
        .with_api_key(api_key);
    let client = Client::with_config(config);
    let mut msgs = Vec::with_capacity(messages.len());
    for (role, content) in messages {
        let m = match role.as_str() {
            "system" => ChatCompletionRequestMessage::System(
                ChatCompletionRequestSystemMessageArgs::default()
                    .content(content.as_str())
                    .build()?,
            ),
            "assistant" => ChatCompletionRequestMessage::Assistant(
                ChatCompletionRequestAssistantMessageArgs::default()
                    .content(content.as_str())
                    .build()?,
            ),
            _ => ChatCompletionRequestMessage::User(
                ChatCompletionRequestUserMessageArgs::default()
                    .content(content.as_str())
                    .build()?,
            ),
        };
        msgs.push(m);
    }
    let req = CreateChatCompletionRequestArgs::default()
        .model(model)
        .messages(msgs)
        .max_tokens(max_tokens as u16)
        .build()?;
    let resp = tokio::time::timeout(timeout, client.chat().create(req))
        .await
        .map_err(|_| anyhow::anyhow!("openai request timed out"))??;
    resp.choices
        .first()
        .and_then(|c| c.message.content.clone())
        .ok_or_else(|| anyhow::anyhow!("empty choices content"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_replaces_dots_and_appends_eos() {
        assert_eq!(query_to_prompt("What.is.this."), "What is this </s>");
    }

    #[test]
    fn request_body_serializes_like_go() {
        let req = TgiRequest {
            inputs: build_inputs("sys", "hello </s>"),
            parameters: TgiParameters {
                max_new_tokens: 20,
                temperature: 1.0,
                top_k: 40,
                top_p: 0.2,
                stop: vec!["</s>".to_string()],
                seed: 42,
            },
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["inputs"], "<|system|>sys<|user|>hello </s>");
        assert_eq!(v["parameters"]["max_new_tokens"], 20);
        assert_eq!(v["parameters"]["seed"], 42);
    }

    #[test]
    fn configured_seed_wins_random_fallback_is_bounded() {
        assert_eq!(resolve_seed(7), 7);
        assert!(resolve_seed(0) < 1000);
    }

    #[tokio::test]
    async fn tgi_client_parses_generated_text() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nhello"})),
            )
            .mount(&server)
            .await;
        let req = TgiRequest {
            inputs: "x".into(),
            parameters: TgiParameters {
                max_new_tokens: 5,
                temperature: 1.0,
                top_k: 40,
                top_p: 0.2,
                stop: vec![],
                seed: 1,
            },
        };
        let out = query_tgi(&server.uri(), &req, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(out, "h1\nh2\nhello");
    }
}

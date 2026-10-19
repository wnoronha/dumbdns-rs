use clap::Parser;

/// DumbDNS in Rust — LLM client in a DNS server.
#[derive(Debug, Clone, Parser)]
#[command(name = "dumbdns", version, about)]
pub struct Config {
    /// DNS listening address
    #[arg(long, env = "DUMBDNS_LISTEN", default_value = "127.0.0.1:5353")]
    pub dns_listening_address: String,

    /// TGI LLM endpoint (POST {endpoint}/generate)
    #[arg(
        long,
        env = "DUMBDNS_LLM_ENDPOINT",
        default_value = "http://localhost:8080"
    )]
    pub llm_endpoint: String,

    /// TGI LLM max new tokens
    #[arg(long, default_value_t = 20)]
    pub llm_max_new_tokens: u32,

    /// TGI LLM temperature
    #[arg(long, default_value_t = 1.0)]
    pub llm_temperature: f32,

    /// TGI LLM top k
    #[arg(long, default_value_t = 40)]
    pub llm_top_k: u32,

    /// TGI LLM top p
    #[arg(long, default_value_t = 0.2)]
    pub llm_top_p: f32,

    /// TGI LLM stop token
    #[arg(long, default_value = "</s>")]
    pub llm_stop: String,

    /// TGI LLM seed (0 = random 0..1000 per request, like Go)
    #[arg(long, default_value_t = 0)]
    pub llm_seed: u64,

    /// System prompt file
    #[arg(long, default_value = "")]
    pub system_prompt: String,

    /// Rate limit in requests per second per client IP (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub rate_limit: u32,

    /// Print verbose output
    #[arg(long, default_value_t = false)]
    pub verbose: bool,

    /// Stateless answer TTL seconds (Go used 3600)
    #[arg(long, default_value_t = 3600)]
    pub ttl_stateless: u32,

    /// Stateful session answer TTL seconds (must be low to avoid cached replays)
    #[arg(long, default_value_t = 5)]
    pub ttl_stateful: u32,

    /// Session idle expiry seconds
    #[arg(long, default_value_t = 600)]
    pub session_ttl_secs: u64,

    /// Max sessions stored (LRU eviction)
    #[arg(long, default_value_t = 1000)]
    pub max_sessions: usize,

    /// Comma-separated allowed client IPs (empty = allow all; localhost default-open)
    #[arg(long, default_value = "")]
    pub allowlist: String,

    /// Shared TSIG-style token: require first QNAME label to equal this (empty = no auth)
    #[arg(long, default_value = "")]
    pub auth_token: String,

    /// Authority zone suffix for session parsing (e.g. "dumb.")
    #[arg(long, default_value = "dumb.")]
    pub zone: String,

    /// LLM request timeout seconds
    #[arg(long, default_value_t = 15)]
    pub llm_timeout_secs: u64,

    /// RAG corpus file (one doc per line, keyword overlap; empty = disabled)
    #[arg(long, default_value = "")]
    pub rag_corpus: String,

    /// DoT listen address (empty = disabled), e.g. 127.0.0.1:853
    #[arg(long, default_value = "")]
    pub dot_address: String,

    /// DoH listen address (empty = disabled), e.g. 127.0.0.1:8443
    #[arg(long, default_value = "")]
    pub doh_address: String,

    /// DoQ listen address (empty = disabled), e.g. 127.0.0.1:853
    #[arg(long, default_value = "")]
    pub doq_address: String,

    /// TLS cert PEM file for DoT/DoH/DoQ (empty = ephemeral self-signed)
    #[arg(long, default_value = "")]
    pub tls_cert: String,

    /// TLS key PEM file for DoT/DoH/DoQ (empty = ephemeral self-signed)
    #[arg(long, default_value = "")]
    pub tls_key: String,

    /// DNS hostname for DoH/DoQ (SNI anchor)
    #[arg(long, default_value = "dumb.local")]
    pub dns_hostname: String,

    /// DNSSEC ED25519 PKCS8 PEM private key file (empty = unsigned)
    #[arg(long, default_value = "")]
    pub dnssec_key: String,

    /// Serve A-record smuggling (first 4 LLM bytes as IPv4 on A queries)
    #[arg(long, default_value_t = false)]
    pub smuggle_a: bool,

    /// Serve AAAA-record smuggling (first 16 LLM bytes as IPv6 on AAAA queries)
    #[arg(long, default_value_t = false)]
    pub smuggle_aaaa: bool,

    /// Serve CNAME smuggling (first 24 LLM bytes as hex labels on CNAME queries)
    #[arg(long, default_value_t = false)]
    pub smuggle_cname: bool,

    /// TOML config file (lowest precedence: CLI > env > file > defaults)
    #[arg(long, default_value = "")]
    pub config: String,

    /// Prometheus /metrics HTTP listen address (empty = disabled)
    #[arg(long, default_value = "")]
    pub metrics_address: String,

    /// Token required as first QNAME label on encrypted transports
    /// (DoT/DoH/DoQ). HTTP headers are not visible to the DNS handler,
    /// so the token travels in the QNAME where TLS protects it in transit.
    #[arg(long, default_value = "")]
    pub doh_bearer: String,

    /// Max QNAME bytes accepted (oversize → REFUSED). DNS max is 255.
    #[arg(long, default_value_t = 200)]
    pub max_qname_bytes: usize,

    /// Max LLM reply bytes kept before char-boundary truncation.
    #[arg(long, default_value_t = 2048)]
    pub max_reply_bytes: usize,

    /// JSONL audit log file (empty = disabled)
    #[arg(long, default_value = "")]
    pub audit_log: String,

    /// Kill-switch file: when present, all LLM paths return REFUSED
    #[arg(long, default_value = "")]
    pub kill_file: String,

    /// Hot-prompt exact-match cache size (0 = disabled)
    #[arg(long, default_value_t = 128)]
    pub cache_size: usize,

    /// Comma-separated deny regexes matched against prompts/values (empty = off)
    #[arg(long, default_value = "")]
    pub deny_patterns: String,

    /// Consecutive LLM failures before the circuit opens (0 = disabled)
    #[arg(long, default_value_t = 5)]
    pub cb_threshold: u32,

    /// Seconds the circuit stays open after tripping
    #[arg(long, default_value_t = 30)]
    pub cb_cooldown_secs: u64,

    /// LLM backend: "tgi" (default) or "openai" for stateful sessions.
    /// For openai, the endpoint is the API base *including* `/v1`
    /// (async-openai appends `/chat/completions`).
    #[arg(long, default_value = "tgi")]
    pub llm_backend: String,

    /// Model name for the OpenAI-compatible backend
    #[arg(long, default_value = "default")]
    pub llm_model: String,

    /// API key for the OpenAI-compatible backend (prefer env OPENAI_API_KEY)
    #[arg(long, env = "OPENAI_API_KEY", default_value = "")]
    pub llm_api_key: String,
}

impl Config {
    /// Read the system-prompt file, returning "" on missing/empty (Go parity: log, continue).
    pub fn load_system_prompt(&self) -> String {
        if self.system_prompt.is_empty() {
            return String::new();
        }
        std::fs::read_to_string(&self.system_prompt).unwrap_or_default()
    }

    pub fn allowlist_ips(&self) -> Vec<String> {
        self.allowlist
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }

    pub fn client_allowed(&self, ip: &str) -> bool {
        let list = self.allowlist_ips();
        list.is_empty() || list.iter().any(|a| a == ip)
    }

    /// Merge a TOML file over fields still at built-in defaults, so
    /// precedence is CLI > env > file > defaults.
    pub fn merge_file(&mut self) -> anyhow::Result<()> {
        if self.config.is_empty() {
            return Ok(());
        }
        let text = std::fs::read_to_string(&self.config)?;
        let v: toml::Value = toml::from_str(&text)?;
        let get = |k: &str| v.get(k);
        if self.dns_listening_address == "127.0.0.1:5353" {
            if let Some(s) = get("dns_listening_address").and_then(|x| x.as_str()) {
                self.dns_listening_address = s.into();
            }
        }
        if self.llm_endpoint == "http://localhost:8080" {
            if let Some(s) = get("llm_endpoint").and_then(|x| x.as_str()) {
                self.llm_endpoint = s.into();
            }
        }
        macro_rules! num {
            ($field:ident, $key:literal, $default:expr) => {
                if self.$field == $default {
                    if let Some(n) = get($key).and_then(|x| x.as_integer()) {
                        self.$field = n as _;
                    }
                }
            };
        }
        macro_rules! strf {
            ($field:ident, $key:literal, $default:expr) => {
                if self.$field == $default {
                    if let Some(s) = get($key).and_then(|x| x.as_str()) {
                        self.$field = s.into();
                    }
                }
            };
        }
        macro_rules! flag {
            ($field:ident, $key:literal) => {
                if !self.$field {
                    if let Some(b) = get($key).and_then(|x| x.as_bool()) {
                        self.$field = b;
                    }
                }
            };
        }
        num!(llm_max_new_tokens, "llm_max_new_tokens", 20);
        num!(llm_top_k, "llm_top_k", 40);
        num!(llm_seed, "llm_seed", 0);
        num!(rate_limit, "rate_limit", 0);
        num!(ttl_stateless, "ttl_stateless", 3600);
        num!(ttl_stateful, "ttl_stateful", 5);
        num!(session_ttl_secs, "session_ttl_secs", 600);
        num!(max_sessions, "max_sessions", 1000);
        num!(llm_timeout_secs, "llm_timeout_secs", 15);
        num!(max_qname_bytes, "max_qname_bytes", 200);
        num!(max_reply_bytes, "max_reply_bytes", 2048);
        num!(cache_size, "cache_size", 128);
        if (self.llm_temperature - 1.0).abs() < f32::EPSILON {
            if let Some(f) = get("llm_temperature").and_then(|x| x.as_float()) {
                self.llm_temperature = f as f32;
            }
        }
        if (self.llm_top_p - 0.2).abs() < 0.001 {
            if let Some(f) = get("llm_top_p").and_then(|x| x.as_float()) {
                self.llm_top_p = f as f32;
            }
        }
        strf!(llm_stop, "llm_stop", "</s>");
        strf!(system_prompt, "system_prompt", String::new());
        strf!(allowlist, "allowlist", String::new());
        strf!(auth_token, "auth_token", String::new());
        strf!(zone, "zone", "dumb.");
        strf!(rag_corpus, "rag_corpus", String::new());
        strf!(dot_address, "dot_address", String::new());
        strf!(doh_address, "doh_address", String::new());
        strf!(doq_address, "doq_address", String::new());
        strf!(tls_cert, "tls_cert", String::new());
        strf!(tls_key, "tls_key", String::new());
        strf!(dns_hostname, "dns_hostname", "dumb.local");
        strf!(dnssec_key, "dnssec_key", String::new());
        strf!(metrics_address, "metrics_address", String::new());
        strf!(doh_bearer, "doh_bearer", String::new());
        strf!(audit_log, "audit_log", String::new());
        strf!(kill_file, "kill_file", String::new());
        strf!(deny_patterns, "deny_patterns", String::new());
        strf!(llm_backend, "llm_backend", "tgi");
        strf!(llm_model, "llm_model", "default");
        strf!(llm_api_key, "llm_api_key", String::new());
        num!(cb_threshold, "cb_threshold", 5);
        num!(cb_cooldown_secs, "cb_cooldown_secs", 30);
        flag!(verbose, "verbose");
        flag!(smuggle_a, "smuggle_a");
        flag!(smuggle_aaaa, "smuggle_aaaa");
        flag!(smuggle_cname, "smuggle_cname");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_go_flags() {
        let cfg = Config::try_parse_from(["dumbdns"]).unwrap();
        assert_eq!(cfg.llm_max_new_tokens, 20);
        assert!((cfg.llm_temperature - 1.0).abs() < f32::EPSILON);
        assert_eq!(cfg.llm_top_k, 40);
        assert!((cfg.llm_top_p - 0.2).abs() < 0.001);
        assert_eq!(cfg.llm_stop, "</s>");
        assert_eq!(cfg.llm_seed, 0);
        assert_eq!(cfg.rate_limit, 0);
        assert!(!cfg.verbose);
        assert_eq!(cfg.ttl_stateless, 3600);
    }

    #[test]
    fn missing_system_prompt_file_returns_empty() {
        let cfg = Config::try_parse_from(["dumbdns", "--system-prompt", "/nonexistent/system.txt"])
            .unwrap();
        assert_eq!(cfg.load_system_prompt(), "");
    }

    #[test]
    fn allowlist_blocks_unlisted_ip() {
        let cfg = Config::try_parse_from(["dumbdns", "--allowlist", "10.0.0.1,10.0.0.2"]).unwrap();
        assert!(cfg.client_allowed("10.0.0.1"));
        assert!(!cfg.client_allowed("9.9.9.9"));
    }

    #[test]
    fn empty_allowlist_allows_all() {
        let cfg = Config::try_parse_from(["dumbdns"]).unwrap();
        assert!(cfg.client_allowed("1.2.3.4"));
    }

    #[test]
    fn toml_file_fills_defaults_cli_wins() {
        let dir = std::env::temp_dir().join("dumbdns_cfg_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dumbdns.toml");
        std::fs::write(
            &path,
            "llm_endpoint = \"http://file:8080\"\nrate_limit = 7\nverbose = true\n",
        )
        .unwrap();
        // File fills defaults.
        let mut cfg =
            Config::try_parse_from(["dumbdns", "--config", path.to_str().unwrap()]).unwrap();
        cfg.merge_file().unwrap();
        assert_eq!(cfg.llm_endpoint, "http://file:8080");
        assert_eq!(cfg.rate_limit, 7);
        assert!(cfg.verbose);
        // CLI wins over file.
        let mut cfg2 = Config::try_parse_from([
            "dumbdns",
            "--config",
            path.to_str().unwrap(),
            "--rate-limit",
            "3",
        ])
        .unwrap();
        cfg2.merge_file().unwrap();
        assert_eq!(cfg2.rate_limit, 3);
        assert_eq!(cfg2.llm_endpoint, "http://file:8080");
    }
}

//! Authoritative DNS request handler: TXT->LLM, DNSKEY, A/AAAA smuggling.
//!
//! Non-TXT queries get empty NOERROR (Go parity) unless a smuggling mode
//! is enabled. TXT answers are `AA=1` with per-mode TTLs; RRSIG is attached
//! only when the resolver sets the DO bit and a zone signer is loaded.
use crate::{
    audit, block::Blocklist, codec, config::Config, dnssec::ZoneSigner, metrics::Metrics, rag,
    session::SessionStore, tgi, txt,
};
use governor::{Quota, RateLimiter};
use hickory_proto::op::{Header, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Protocol, Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cached stateless answer: TXT strings + TTL + insertion time.
type CacheEntry = (Vec<String>, u32, Instant);

/// Shared state for all DNS transports (UDP/TCP/DoT/DoH/DoQ serve one handler).
/// `limiter` is lock-free (governor DashMap); `cache` uses a poison-recovering Mutex.
pub struct DumbDnsHandler {
    pub cfg: Config,
    pub system_prompt: String,
    pub corpus: Vec<String>,
    pub sessions: SessionStore,
    pub limiter: Option<
        RateLimiter<
            String,
            governor::state::keyed::DashMapStateStore<String>,
            governor::clock::DefaultClock,
        >,
    >,
    pub cache: Option<Mutex<lru::LruCache<String, CacheEntry>>>,
    pub metrics: Option<Arc<Metrics>>,
    pub signer: Option<ZoneSigner>,
    pub block: Blocklist,
    cb_fail: std::sync::atomic::AtomicU32,
    cb_open_until: std::sync::atomic::AtomicU64,
}

impl DumbDnsHandler {
    pub fn new(cfg: Config, metrics: Option<Arc<Metrics>>) -> anyhow::Result<Self> {
        let system_prompt = cfg.load_system_prompt();
        let corpus = rag::load_corpus(&cfg.rag_corpus);
        let sessions = SessionStore::open_in_memory(cfg.max_sessions, cfg.session_ttl_secs)?;
        let signer = if cfg.dnssec_key.is_empty() {
            None
        } else {
            Some(ZoneSigner::load(&cfg.dnssec_key, &cfg.zone)?)
        };
        let limiter = NonZeroU32::new(cfg.rate_limit)
            .map(|n| RateLimiter::dashmap(Quota::per_second(n).allow_burst(n)));
        let block = Blocklist::compile(&cfg.deny_patterns)?;
        let cache =
            std::num::NonZeroUsize::new(cfg.cache_size).map(|n| Mutex::new(lru::LruCache::new(n)));
        Ok(Self {
            cfg,
            system_prompt,
            corpus,
            sessions,
            limiter,
            cache,
            metrics,
            signer,
            block,
            cb_fail: std::sync::atomic::AtomicU32::new(0),
            cb_open_until: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn check_rate(&self, ip: &str) -> bool {
        match &self.limiter {
            None => true,
            Some(lim) => lim.check_key(&ip.to_string()).is_ok(),
        }
    }

    fn epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn cb_allows(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.cfg.cb_threshold == 0 {
            return true;
        }
        self.cb_open_until.load(Ordering::Relaxed) <= Self::epoch()
    }

    fn cb_report(&self, ok: bool) {
        use std::sync::atomic::Ordering;
        if self.cfg.cb_threshold == 0 {
            return;
        }
        if ok {
            self.cb_fail.store(0, Ordering::Relaxed);
        } else {
            let n = self.cb_fail.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= self.cfg.cb_threshold {
                self.cb_open_until
                    .store(Self::epoch() + self.cfg.cb_cooldown_secs, Ordering::Relaxed);
            }
        }
    }

    fn count(&self, qtype: &str, result: &str) {
        if let Some(m) = &self.metrics {
            m.queries.with_label_values(&[qtype, result]).inc();
        }
    }

    fn audit(
        &self,
        client: &str,
        transport: &str,
        qtype: &str,
        qname: &str,
        result: &str,
        reply_bytes: usize,
    ) {
        audit::append(
            &self.cfg.audit_log,
            &audit::entry(client, transport, qtype, qname, result, reply_bytes),
        );
    }

    fn zone_trimmed(&self) -> String {
        self.cfg.zone.trim_end_matches('.').to_lowercase()
    }

    /// Zone as FQDN suffix, e.g. ".kv.dumb." — hickory names carry trailing dots.
    /// Kill-switch: when the file exists, all LLM paths refuse.
    fn killed(&self) -> bool {
        !self.cfg.kill_file.is_empty() && std::path::Path::new(&self.cfg.kill_file).exists()
    }

    fn cache_get(&self, key: &str, ttl_bound: u32) -> Option<(Vec<String>, u32)> {
        let cache = self.cache.as_ref()?;
        let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
        let (parts, ttl, inserted) = c.get(key)?.clone();
        if inserted.elapsed() > Duration::from_secs(ttl_bound.min(ttl) as u64) {
            c.pop(key);
            return None;
        }
        Some((parts, ttl))
    }

    fn cache_put(&self, key: String, parts: Vec<String>, ttl: u32) {
        if let Some(cache) = &self.cache {
            let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
            c.put(key, (parts, ttl, Instant::now()));
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DumbDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let info = request.request_info();
        let ip = info.src.ip().to_string();
        let qtype = info.query.query_type();
        let name = info.query.name().to_string();
        let header = info.header;
        let transport = format!("{:?}", request.protocol());

        if !self.cfg.client_allowed(&ip) {
            self.count("any", "denied");
            self.audit(&ip, &transport, "any", &name, "denied", 0);
            return response_handle
                .send_response(builder.error_msg(header, ResponseCode::Refused))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }
        if !self.check_rate(&ip) {
            self.count("any", "rate_limited");
            self.audit(&ip, &transport, "any", &name, "rate_limited", 0);
            return response_handle
                .send_response(builder.error_msg(header, ResponseCode::Refused))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        if name.len() > self.cfg.max_qname_bytes {
            self.count("any", "oversize");
            self.audit(&ip, &transport, "any", &name, "oversize", 0);
            return response_handle
                .send_response(builder.error_msg(header, ResponseCode::Refused))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        // Setter path (RFC 2136 UPDATE): writes require a configured token
        // (auth_token on any transport, or doh_bearer on encrypted ones) AND
        // an encrypted transport or loopback source. No token configured or
        // plaintext remote => all writes refused (secure default).
        if request.op_code() == OpCode::Update {
            let first = name.split('.').next().unwrap_or("");
            let token_ok = (!self.cfg.auth_token.is_empty() && first == self.cfg.auth_token)
                || (!self.cfg.doh_bearer.is_empty()
                    && matches!(
                        request.protocol(),
                        Protocol::Https | Protocol::Quic | Protocol::Tls
                    )
                    && first == self.cfg.doh_bearer);
            let channel_ok = matches!(
                request.protocol(),
                Protocol::Https | Protocol::Quic | Protocol::Tls
            ) || info.src.ip().is_loopback();
            if !(token_ok && channel_ok) {
                self.count("UPDATE", "write_denied");
                self.audit(&ip, &transport, "UPDATE", &name, "write_denied", 0);
                return response_handle
                    .send_response(builder.error_msg(header, ResponseCode::Refused))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
            let mut stored = 0usize;
            let mut mem_stored = 0usize;
            // Collect first so a blocked value refuses the whole update
            // before anything is stored.
            let mut pending: Vec<(String, String, String)> = vec![];
            for rec in request.name_servers() {
                let owner = rec.name().to_string().to_lowercase();
                // Feature form: `{id}._{kv,c2,mem}.zone`; other names ignored.
                let (key, kind) = match codec::split_infra(&owner, &self.cfg.zone) {
                    Some((id, Some(f), _)) if f == "_kv" || f == "_c2" => (id, "kv"),
                    Some((id, Some(f), _)) if f == "_mem" => (id, "mem"),
                    _ => continue,
                };
                let value: Option<String> = match rec.data() {
                    Some(RData::TXT(t)) => Some(
                        t.iter()
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                            .collect::<Vec<_>>()
                            .join(""),
                    ),
                    _ => None,
                };
                if let Some(v) = value {
                    if !self.block.is_empty() && self.block.blocked(&v) {
                        self.count("UPDATE", "blocked");
                        self.audit(&ip, &transport, "UPDATE", &name, "blocked", 0);
                        return response_handle
                            .send_response(builder.error_msg(header, ResponseCode::Refused))
                            .await
                            .unwrap_or_else(|_| Header::response_from_request(header).into());
                    }
                    pending.push((kind.to_string(), key, v));
                }
            }
            for (kind, key, v) in pending {
                if kind == "mem" {
                    if self.sessions.append(&key, "memory", v.trim()).is_ok() {
                        mem_stored += 1;
                    }
                } else if self
                    .sessions
                    .kv_put(&key, v.trim(), self.cfg.max_reply_bytes)
                    .is_ok()
                {
                    stored += 1;
                }
            }
            self.count("UPDATE", "stored");
            self.audit(
                &ip,
                &transport,
                "UPDATE",
                &name,
                "stored",
                stored + mem_stored,
            );
            let mut h = Header::response_from_request(header);
            h.set_authoritative(true);
            return response_handle
                .send_response(builder.build(h, [], [], [], []))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        // Capability namespaces: `{id}[._feature].zone` names are
        // capabilities (unguessable IDs); raw prompts are not. Auth tokens
        // gate raw prompts and all writes, not namespaced reads.
        let infra = codec::split_infra(&name, &self.cfg.zone);
        let namespaced = match &infra {
            Some((id, None, _)) => !id.is_empty() && !id.starts_with('_'),
            Some(_) => true,
            None => false,
        };

        // Downstream paging: `{id}._page.{N}.{zone}` serves the Nth
        // 255B chunk of the session's last full reply.
        let mut page_req: Option<(String, usize)> = None;
        if let Some((id, Some(f), args)) = &infra {
            if f == "_page" {
                if let Some(nstr) = args.first() {
                    if let Ok(n) = nstr.parse::<usize>() {
                        page_req = Some((id.clone(), n));
                    }
                }
            }
        }
        if let Some((sid, n)) = page_req {
            if let Some(full) = self.sessions.reply_get(&sid) {
                let parts = txt::chunk_txt(&full);
                if let Some(page) = parts.get(n) {
                    self.count("TXT", "page_hit");
                    self.audit(&ip, &transport, "TXT", &name, "page_hit", page.len());
                    let rdata = RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![page.clone()]));
                    let mut qname: Name = info.query.name().clone().into();
                    qname.set_fqdn(true);
                    let rec = Record::from_rdata(qname, self.cfg.ttl_stateful, rdata);
                    let mut h = Header::response_from_request(header);
                    h.set_authoritative(true);
                    let answers = [rec];
                    return response_handle
                        .send_response(builder.build(h, answers.iter(), [], [], []))
                        .await
                        .unwrap_or_else(|_| Header::response_from_request(header).into());
                }
            }
            self.count("TXT", "page_miss");
            self.audit(&ip, &transport, "TXT", &name, "page_miss", 0);
            let mut h = Header::response_from_request(header);
            h.set_authoritative(true);
            return response_handle
                .send_response(builder.build(h, [], [], [], []))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        // DNSKEY: serve zone key for validators / C2 credibility.
        if qtype == RecordType::DNSKEY {
            if let Some(zs) = &self.signer {
                let rec = zs.dnskey_record();
                self.count("DNSKEY", "ok");
                self.audit(&ip, &transport, "DNSKEY", &name, "ok", 0);
                let mut h = Header::response_from_request(header);
                h.set_authoritative(true);
                let answers = [rec];
                return response_handle
                    .send_response(builder.build(h, answers.iter(), [], [], []))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
            self.count("DNSKEY", "empty");
            let mut h = Header::response_from_request(header);
            h.set_authoritative(true);
            return response_handle
                .send_response(builder.build(h, [], [], [], []))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        // Kill-switch: file present => all LLM paths refuse (DNSKEY/empty still served).
        if self.killed()
            && (qtype == RecordType::TXT
                || (qtype == RecordType::A && self.cfg.smuggle_a)
                || (qtype == RecordType::AAAA && self.cfg.smuggle_aaaa))
        {
            self.count(&qtype.to_string(), "killed");
            self.audit(&ip, &transport, &qtype.to_string(), &name, "killed", 0);
            return response_handle
                .send_response(builder.error_msg(header, ResponseCode::Refused))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        // A / AAAA smuggling (opt-in): encode LLM bytes as addresses for
        // restrictive resolvers that strip TXT.
        if qtype == RecordType::A || qtype == RecordType::AAAA || qtype == RecordType::CNAME {
            let enabled = (qtype == RecordType::A && self.cfg.smuggle_a)
                || (qtype == RecordType::AAAA && self.cfg.smuggle_aaaa)
                || (qtype == RecordType::CNAME && self.cfg.smuggle_cname);
            if !enabled {
                self.count(&qtype.to_string(), "empty");
                let mut h = Header::response_from_request(header);
                h.set_authoritative(true);
                return response_handle
                    .send_response(builder.build(h, [], [], [], []))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
            let prompt_text = tgi::query_to_prompt(&name);
            if !self.block.is_empty() && self.block.blocked(&prompt_text) {
                self.count(&qtype.to_string(), "blocked");
                self.audit(&ip, &transport, &qtype.to_string(), &name, "blocked", 0);
                return response_handle
                    .send_response(builder.error_msg(header, ResponseCode::Refused))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
            let sys = self.system_prompt.clone();
            let req_body = tgi::TgiRequest {
                inputs: tgi::build_inputs(&sys, &prompt_text),
                parameters: tgi::TgiParameters {
                    max_new_tokens: self.cfg.llm_max_new_tokens,
                    temperature: self.cfg.llm_temperature,
                    top_k: self.cfg.llm_top_k,
                    top_p: self.cfg.llm_top_p,
                    stop: vec![self.cfg.llm_stop.clone()],
                    seed: tgi::resolve_seed(self.cfg.llm_seed),
                },
            };
            let raw = if self.cb_allows() {
                match tgi::query_tgi(
                    &self.cfg.llm_endpoint,
                    &req_body,
                    Duration::from_secs(self.cfg.llm_timeout_secs),
                )
                .await
                {
                    Ok(r) => {
                        self.cb_report(true);
                        r
                    }
                    Err(_) => {
                        self.cb_report(false);
                        self.count(&qtype.to_string(), "llm_error");
                        String::new()
                    }
                }
            } else {
                self.count(&qtype.to_string(), "circuit_open");
                String::new()
            };
            self.count(&qtype.to_string(), "ok");
            self.audit(&ip, &transport, &qtype.to_string(), &name, "ok", 0);
            let bytes = txt::clean_response(&raw).into_bytes();
            let mut qname: Name = info.query.name().clone().into();
            qname.set_fqdn(true);
            let rdata = if qtype == RecordType::CNAME {
                let hex: String = bytes.iter().take(24).map(|b| format!("{b:02x}")).collect();
                let target = format!("{hex}.c.{}", self.zone_trimmed());
                let mut cname: Name = target.parse().unwrap_or_else(|_| qname.clone());
                cname.set_fqdn(true);
                RData::CNAME(hickory_proto::rr::rdata::CNAME(cname))
            } else if qtype == RecordType::A {
                let mut oct = [0u8; 4];
                oct.copy_from_slice(&bytes[..bytes.len().min(4)]);
                if oct == [0, 0, 0, 0] {
                    oct = [127, 0, 0, 1];
                }
                RData::A(hickory_proto::rr::rdata::A::new(
                    oct[0], oct[1], oct[2], oct[3],
                ))
            } else {
                let mut b16 = [0u8; 16];
                b16.copy_from_slice(&bytes[..bytes.len().min(16)]);
                RData::AAAA(hickory_proto::rr::rdata::AAAA::new(
                    u16::from_be_bytes([b16[0], b16[1]]),
                    u16::from_be_bytes([b16[2], b16[3]]),
                    u16::from_be_bytes([b16[4], b16[5]]),
                    u16::from_be_bytes([b16[6], b16[7]]),
                    u16::from_be_bytes([b16[8], b16[9]]),
                    u16::from_be_bytes([b16[10], b16[11]]),
                    u16::from_be_bytes([b16[12], b16[13]]),
                    u16::from_be_bytes([b16[14], b16[15]]),
                ))
            };
            let rec = Record::from_rdata(qname, self.cfg.ttl_stateless, rdata);
            let mut h = Header::response_from_request(header);
            h.set_authoritative(true);
            let answers = [rec];
            return response_handle
                .send_response(builder.build(h, answers.iter(), [], [], []))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        if qtype != RecordType::TXT {
            self.count(&qtype.to_string(), "empty");
            let mut h = Header::response_from_request(header);
            h.set_authoritative(true);
            return response_handle
                .send_response(builder.build(h, [], [], [], []))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        // Optional token auth on first label (raw prompts only).
        if !namespaced && !self.cfg.auth_token.is_empty() {
            let first = name.split('.').next().unwrap_or("");
            if first != self.cfg.auth_token {
                self.count("TXT", "denied");
                return response_handle
                    .send_response(builder.error_msg(header, ResponseCode::Refused))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
        }

        // Encrypted-transport token: hickory does not expose HTTP headers to
        // the handler, so the bearer travels as the first QNAME label where
        // TLS still protects it in transit (NOT safe on plaintext UDP/TCP —
        // use auth_token + firewall there).
        if !namespaced && !self.cfg.doh_bearer.is_empty() {
            match request.protocol() {
                Protocol::Https | Protocol::Quic | Protocol::Tls => {
                    let first = name.split('.').next().unwrap_or("");
                    if first != self.cfg.doh_bearer {
                        self.count("encrypted", "denied");
                        return response_handle
                            .send_response(builder.error_msg(header, ResponseCode::Refused))
                            .await
                            .unwrap_or_else(|_| Header::response_from_request(header).into());
                    }
                }
                _ => {}
            }
        }

        let cacheable = self.cfg.auth_token.is_empty() && self.cfg.doh_bearer.is_empty();
        let cache_key = format!("TXT:{}", name.to_lowercase());
        if cacheable {
            if let Some((hit, ttl)) = self.cache_get(&cache_key, self.cfg.ttl_stateless) {
                let bytes: usize = hit.iter().map(|x| x.len()).sum();
                self.count("TXT", "cache_hit");
                self.audit(&ip, &transport, "TXT", &name, "cache_hit", bytes);
                let rdata = RData::TXT(hickory_proto::rr::rdata::TXT::new(hit));
                let mut qname: Name = info.query.name().clone().into();
                qname.set_fqdn(true);
                let rec = Record::from_rdata(qname, ttl, rdata);
                let mut h = Header::response_from_request(header);
                h.set_authoritative(true);
                let answers = [rec];
                return response_handle
                    .send_response(builder.build(h, answers.iter(), [], [], []))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
        }

        if let Some((id, Some(f), _)) = &infra {
            if f == "_kv" || f == "_c2" {
                match self.sessions.kv_get(id) {
                    Some(v) => {
                        let parts = txt::chunk_txt(&v);
                        let bytes: usize = parts.iter().map(|x| x.len()).sum();
                        self.count("TXT", "kv_hit");
                        self.audit(&ip, &transport, "TXT", &name, "kv_hit", bytes);
                        let rdata = RData::TXT(hickory_proto::rr::rdata::TXT::new(parts));
                        let mut qname: Name = info.query.name().clone().into();
                        qname.set_fqdn(true);
                        let rec = Record::from_rdata(qname, self.cfg.ttl_stateless, rdata);
                        let mut h = Header::response_from_request(header);
                        h.set_authoritative(true);
                        let answers = [rec];
                        return response_handle
                            .send_response(builder.build(h, answers.iter(), [], [], []))
                            .await
                            .unwrap_or_else(|_| Header::response_from_request(header).into());
                    }
                    None => {
                        self.count("TXT", "kv_miss");
                        self.audit(&ip, &transport, "TXT", &name, "kv_miss", 0);
                        let mut h = Header::response_from_request(header);
                        h.set_authoritative(true);
                        return response_handle
                            .send_response(builder.build(h, [], [], [], []))
                            .await
                            .unwrap_or_else(|_| Header::response_from_request(header).into());
                    }
                }
            }
        }

        // One rule: every in-zone name is (id, feature, args); a missing
        // feature is `_llm` with empty text (continue/flush). No name-derived
        // prompts: the name carries identity, the args carry text. An id that
        // equals the auth token never becomes a session (probing guard).
        let token_id = !self.cfg.auth_token.is_empty()
            && matches!(&infra, Some((id, _, _)) if id == &self.cfg.auth_token);
        let (prompt_text, ttl, stateful, sess_id): (String, u32, bool, Option<String>) =
            match &infra {
                Some((id, Some(f), args)) if f == "_llm" && !id.starts_with('_') && !token_id => (
                    format!("{} </s>", args.join(" ")),
                    self.cfg.ttl_stateful,
                    true,
                    Some(id.clone()),
                ),
                Some((id, None, _)) if !id.is_empty() && !id.starts_with('_') && !token_id => {
                    (String::new(), self.cfg.ttl_stateful, true, Some(id.clone()))
                }
                _ => (
                    tgi::query_to_prompt(&name),
                    self.cfg.ttl_stateless,
                    false,
                    None,
                ),
            };

        // Fragment buffering: `{id}._part.{N}.{chunk}` queries are stored,
        // not sent to the LLM. This sits outside the stateful gate because
        // part-names are features, not sessions. A plain session query
        // flushes buffered fragments into its prompt, in order.
        let mut prompt_text = prompt_text;
        if let Some((id, Some(f), args)) = &infra {
            if f == "_part" {
                let seq = args
                    .first()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let chunk = args[1..].join(".");
                let _ = self.sessions.frag_store(id, seq, &chunk);
                self.count("TXT", "frag_ack");
                self.audit(&ip, &transport, "TXT", &name, "frag_ack", 0);
                let ack = format!("ACK {id} {seq}");
                let rdata = RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![ack]));
                let mut qname: Name = info.query.name().clone().into();
                qname.set_fqdn(true);
                let rec = Record::from_rdata(qname, self.cfg.ttl_stateful, rdata);
                let mut h = Header::response_from_request(header);
                h.set_authoritative(true);
                let answers = [rec];
                return response_handle
                    .send_response(builder.build(h, answers.iter(), [], [], []))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
        }
        if stateful {
            if let Some(sid) = &sess_id {
                let buffered = self.sessions.frag_take(sid);
                if !buffered.is_empty() {
                    prompt_text = format!("{} {}", buffered.join(" "), prompt_text);
                }
            }
        }

        // Spend guard: empty prompt, empty buffer, no history means there is
        // nothing to ask. Answer empty without touching the model.
        if stateful {
            let bare = prompt_text
                .trim()
                .strip_suffix("</s>")
                .unwrap_or(&prompt_text)
                .trim()
                .is_empty();
            let hist_len = sess_id
                .as_ref()
                .and_then(|sid| self.sessions.get(sid).ok())
                .map(|h| h.len())
                .unwrap_or(0);
            if bare && hist_len == 0 {
                self.count("TXT", "empty_prompt");
                self.audit(&ip, &transport, "TXT", &name, "empty_prompt", 0);
                let mut h = Header::response_from_request(header);
                h.set_authoritative(true);
                return response_handle
                    .send_response(builder.build(h, [], [], [], []))
                    .await
                    .unwrap_or_else(|_| Header::response_from_request(header).into());
            }
        }

        if !self.block.is_empty() && self.block.blocked(&prompt_text) {
            self.count("TXT", "blocked");
            self.audit(&ip, &transport, "TXT", &name, "blocked", 0);
            return response_handle
                .send_response(builder.error_msg(header, ResponseCode::Refused))
                .await
                .unwrap_or_else(|_| Header::response_from_request(header).into());
        }

        let mut sys = self.system_prompt.clone();
        if !self.corpus.is_empty() {
            let hits = rag::retrieve(&self.corpus, &prompt_text, 3);
            if !hits.is_empty() {
                sys.push_str("\n\nContext:\n");
                sys.push_str(&hits.join("\n"));
            }
        }

        if stateful {
            if let Some(sid) = &sess_id {
                let facts = self.sessions.memories(sid, 5);
                if !facts.is_empty() {
                    sys.push_str("\n\nKnown facts:\n");
                    sys.push_str(&facts.join("\n"));
                }
            }
        }

        let t0 = Instant::now();
        let use_openai = stateful && self.cfg.llm_backend == "openai";
        let backend = if use_openai { "openai" } else { "tgi" };
        let req_body = tgi::TgiRequest {
            inputs: tgi::build_inputs(&sys, &prompt_text),
            parameters: tgi::TgiParameters {
                max_new_tokens: self.cfg.llm_max_new_tokens,
                temperature: self.cfg.llm_temperature,
                top_k: self.cfg.llm_top_k,
                top_p: self.cfg.llm_top_p,
                stop: vec![self.cfg.llm_stop.clone()],
                seed: tgi::resolve_seed(self.cfg.llm_seed),
            },
        };
        // Stateful OpenAI path: full turn history + memories as chat messages.
        let chat_messages: Vec<(String, String)> = if use_openai {
            let sid = sess_id.clone().unwrap_or_default();
            let mut msgs = vec![("system".to_string(), sys.clone())];
            msgs.extend(self.sessions.get(&sid).unwrap_or_default());
            msgs.push(("user".to_string(), prompt_text.clone()));
            msgs
        } else {
            vec![]
        };
        let raw = if self.cb_allows() {
            let res = if use_openai {
                tgi::query_chat(
                    &self.cfg.llm_endpoint,
                    &self.cfg.llm_model,
                    &self.cfg.llm_api_key,
                    &chat_messages,
                    self.cfg.llm_max_new_tokens,
                    Duration::from_secs(self.cfg.llm_timeout_secs),
                )
                .await
            } else {
                tgi::query_tgi(
                    &self.cfg.llm_endpoint,
                    &req_body,
                    Duration::from_secs(self.cfg.llm_timeout_secs),
                )
                .await
            };
            match res {
                Ok(r) => {
                    self.cb_report(true);
                    r
                }
                Err(_) => {
                    self.cb_report(false);
                    self.count("TXT", "llm_error");
                    String::new()
                }
            }
        } else {
            self.count("TXT", "circuit_open");
            String::new()
        };
        if let Some(m) = &self.metrics {
            m.llm_latency
                .with_label_values(&[backend])
                .observe(t0.elapsed().as_secs_f64());
        }
        self.count("TXT", "ok");

        let mut cleaned = txt::clean_response(&raw);
        if stateful {
            if let Some(sid) = &sess_id {
                self.sessions.reply_store(sid, &cleaned);
            }
        }
        let (capped, was_cut) = txt::truncate_bytes(&cleaned, self.cfg.max_reply_bytes);
        cleaned = capped;
        if was_cut {
            self.count("TXT", "truncated");
        }
        if stateful {
            if let Some(sid) = &sess_id {
                let _ = self.sessions.append(sid, "user", &prompt_text);
                let _ = self.sessions.append(sid, "assistant", &cleaned);
            }
        }
        let parts = txt::chunk_txt(&cleaned);
        if !stateful && cacheable {
            self.cache_put(cache_key, parts.clone(), ttl);
        }
        let reply_bytes: usize = parts.iter().map(|x| x.len()).sum();
        self.audit(&ip, &transport, "TXT", &name, "ok", reply_bytes);
        let rdata = RData::TXT(hickory_proto::rr::rdata::TXT::new(parts));
        let mut qname: Name = info.query.name().clone().into();
        qname.set_fqdn(true);
        let rec = Record::from_rdata(qname, ttl, rdata);
        // DNSSEC: attach RRSIG when the resolver sets DO and we have a key.
        let do_bit = request.edns().map(|e| e.dnssec_ok()).unwrap_or(false);
        let mut owned: Vec<Record> = vec![rec];
        if do_bit {
            if let Some(zs) = &self.signer {
                match zs.sign_rrset(&owned) {
                    Ok(sig) => owned.push(sig),
                    Err(e) => tracing::warn!("dnssec sign failed: {e:#}"),
                }
            }
        }
        // EDNS/TC: on UDP, honor the client's advertised max payload.
        // Without EDNS we preserve legacy behavior (send anyway).
        if matches!(request.protocol(), Protocol::Udp) {
            if let Some(edns) = request.edns() {
                let size: usize = owned
                    .iter()
                    .map(|r| {
                        r.data()
                            .map(|d| match d {
                                RData::TXT(t) => t.iter().map(|b| b.len()).sum(),
                                _ => 0,
                            })
                            .unwrap_or(0)
                    })
                    .sum::<usize>()
                    + 100;
                if size > edns.max_payload() as usize {
                    self.count("TXT", "truncated_tc");
                    self.audit(&ip, &transport, "TXT", &name, "truncated_tc", 0);
                    let mut h = Header::response_from_request(header);
                    h.set_authoritative(true);
                    h.set_truncated(true);
                    return response_handle
                        .send_response(builder.build(h, [], [], [], []))
                        .await
                        .unwrap_or_else(|_| Header::response_from_request(header).into());
                }
            }
        }
        let mut h = Header::response_from_request(header);
        h.set_authoritative(true);
        response_handle
            .send_response(builder.build(h, owned.iter(), [], [], []))
            .await
            .unwrap_or_else(|_| Header::response_from_request(header).into())
    }
}

//! Blackbox tests: live DNS server + stubbed LLM, no external network.

use assert_cmd::Command;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use predicates::prelude::*;
use std::io::Write;
use std::net::UdpSocket;
use std::process::Command as ProcCommand;
use std::str::FromStr;
use std::time::Duration;

#[test]
fn help_lists_all_go_parity_flags() {
    let mut cmd = Command::cargo_bin("dumbdns").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("dns-listening-address"))
        .stdout(predicate::str::contains("llm-endpoint"))
        .stdout(predicate::str::contains("llm-max-new-tokens"))
        .stdout(predicate::str::contains("llm-temperature"))
        .stdout(predicate::str::contains("llm-top-k"))
        .stdout(predicate::str::contains("llm-top-p"))
        .stdout(predicate::str::contains("llm-stop"))
        .stdout(predicate::str::contains("llm-seed"))
        .stdout(predicate::str::contains("system-prompt"))
        .stdout(predicate::str::contains("rate-limit"))
        .stdout(predicate::str::contains("verbose"))
        .stdout(predicate::str::contains("ttl-stateless"))
        .stdout(predicate::str::contains("allowlist"))
        .stdout(predicate::str::contains("auth-token"));
}

/// RAII server handle: kills the child on drop, so a panicking assert can
/// never orphan a server (orphans hold test pipes open and steal ports).
struct ServerGuard(std::process::Child);
impl ServerGuard {
    fn spawn(args: &[&str]) -> Self {
        let bin = assert_cmd::cargo::cargo_bin("dumbdns");
        Self(
            ProcCommand::new(bin)
                .args(args)
                .spawn()
                .expect("server spawn"),
        )
    }
}
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn dns_query(addr: &str, name: &str, qtype: RecordType) -> Message {
    dns_query_edns(addr, name, qtype, false)
}

fn dns_query_edns(addr: &str, name: &str, qtype: RecordType, dnssec_ok: bool) -> Message {
    dns_query_edns_payload(addr, name, qtype, dnssec_ok, 4096)
}

fn dns_query_edns_payload(
    addr: &str,
    name: &str,
    qtype: RecordType,
    dnssec_ok: bool,
    max_payload: u16,
) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut msg = Message::new();
    msg.set_id(1234)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
    if dnssec_ok {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_dnssec_ok(true).set_max_payload(max_payload);
        msg.set_edns(edns);
    } else {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(max_payload);
        msg.set_edns(edns);
    }
    let bytes = msg.to_bytes().unwrap();
    sock.send_to(&bytes, addr).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    Message::from_bytes(&buf[..n]).unwrap()
}

#[tokio::test]
async fn live_txt_query_returns_llm_answer_chunked() {
    // Stub TGI endpoint with a long response to exercise 255B chunking.
    let tgi = wiremock::MockServer::start().await;
    let long = format!("h1\nh2\n{}", "A".repeat(600));
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": long})),
        )
        .mount(&tgi)
        .await;

    let port = 15353;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    // Wait for bind.
    let mut ready = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(sock) = UdpSocket::bind("127.0.0.1:0") {
            sock.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut msg = Message::new();
            msg.set_id(1)
                .set_message_type(MessageType::Query)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(true);
            msg.add_query(Query::query(
                Name::from_str("ping.").unwrap(),
                RecordType::A,
            ));
            if sock.send_to(&msg.to_bytes().unwrap(), &addr).is_ok()
                && sock.recv_from(&mut [0u8; 512]).is_ok()
            {
                ready = true;
                break;
            }
        }
    }
    assert!(ready, "server did not start");

    // TXT query -> LLM stub answer, authoritative, chunks <= 255B.
    let resp = dns_query(&addr, "hello.world.", RecordType::TXT);
    assert!(resp.authoritative());
    assert_eq!(resp.answers().len(), 1);
    if let Some(hickory_proto::rr::RData::TXT(t)) = resp.answers()[0].data() {
        let joined: String = t
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert_eq!(joined.len(), 600);
        assert!(t.iter().all(|b| b.len() <= 255));
    } else {
        panic!("expected TXT");
    }

    // Non-TXT -> empty NOERROR (Go parity).
    let resp_a = dns_query(&addr, "hello.world.", RecordType::A);
    assert!(resp_a.answers().is_empty());
}

#[tokio::test]
async fn dnskey_without_key_returns_empty_noerror() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15355;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "dumb.", RecordType::DNSKEY);
    assert!(resp.answers().is_empty());
}

#[tokio::test]
async fn smuggle_a_returns_ipv4_from_llm_bytes() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nABCDrest"})),
        )
        .mount(&tgi)
        .await;
    let port = 15356;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--smuggle-a",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "hello.", RecordType::A);
    assert_eq!(resp.answers().len(), 1);
    assert!(matches!(
        resp.answers()[0].data(),
        Some(hickory_proto::rr::RData::A(_))
    ));
}

#[tokio::test]
async fn smuggle_aaaa_returns_ipv6_from_llm_bytes() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\n0123456789abcdef"})),
        )
        .mount(&tgi)
        .await;
    let port = 15368;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--smuggle-aaaa",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "hello.", RecordType::AAAA);
    assert_eq!(resp.answers().len(), 1);
    assert!(matches!(
        resp.answers()[0].data(),
        Some(hickory_proto::rr::RData::AAAA(_))
    ));
}

#[tokio::test]
async fn dot_listener_binds_and_accepts_tcp() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15357;
    let addr = format!("127.0.0.1:{port}");
    let dot = "127.0.0.1:15533";
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--dot-address",
        dot,
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let stream =
        std::net::TcpStream::connect_timeout(&dot.parse().unwrap(), Duration::from_secs(3));
    assert!(stream.is_ok(), "DoT listener did not accept TCP");
}

#[tokio::test]
async fn metrics_endpoint_serves_counters() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15358;
    let addr = format!("127.0.0.1:{port}");
    let madd = "127.0.0.1:15580";
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--metrics-address",
        madd,
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // Counters only render after first observation — generate one query.
    let _ = dns_query(&addr, "hello.", RecordType::A);
    let body = reqwest::get(format!("http://{madd}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("dumbdns_queries_total"));
}

#[tokio::test]
async fn governor_rate_limit_refuses_burst() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "x\ny\nz"})),
        )
        .mount(&tgi)
        .await;
    let port = 15359;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--rate-limit",
        "1",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let mut refused = 0;
    for _ in 0..5 {
        let resp = dns_query(&addr, "hello.", RecordType::TXT);
        if resp.response_code() == hickory_proto::op::ResponseCode::Refused {
            refused += 1;
        }
    }
    assert!(
        refused >= 1,
        "governor never refused a 5-query burst at 1rps"
    );
}

#[tokio::test]
async fn allowlist_refuses_unlisted_client() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "x\ny\nz"})),
        )
        .mount(&tgi)
        .await;
    let port = 15354;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--allowlist",
        "10.99.99.99",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "hello.", RecordType::TXT);
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
    let _ = Write::write_all(&mut std::io::stderr(), b"");
}

fn write_ed25519_pem(dir: &tempfile::TempDir) -> String {
    use base64::Engine;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    let path = dir.path().join("dnssec.pem");
    std::fs::write(&path, pem).unwrap();
    path.to_str().unwrap().to_string()
}

#[tokio::test]
async fn dnssec_rrsig_attached_on_do_bit() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nsigned"})),
        )
        .mount(&tgi)
        .await;
    let dir = tempfile::TempDir::new().unwrap();
    let key = write_ed25519_pem(&dir);
    let port = 15360;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--dnssec-key",
        &key,
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // DO bit set -> TXT + RRSIG.
    let resp = dns_query_edns(&addr, "sigtest._llm.hello.dumb.", RecordType::TXT, true);
    let types: Vec<_> = resp.answers().iter().map(|r| r.record_type()).collect();
    assert!(types.contains(&RecordType::TXT), "missing TXT: {types:?}");
    assert!(
        types.contains(&RecordType::RRSIG),
        "missing RRSIG: {types:?}"
    );
    // No DO bit -> TXT only.
    let plain = dns_query(&addr, "sigtest._llm.hello.dumb.", RecordType::TXT);
    let ptypes: Vec<_> = plain.answers().iter().map(|r| r.record_type()).collect();
    assert!(!ptypes.contains(&RecordType::RRSIG));
    // Apex DNSKEY served.
    let dnskey = dns_query(&addr, "dumb.", RecordType::DNSKEY);
    assert_eq!(dnskey.answers().len(), 1);
    assert_eq!(dnskey.answers()[0].record_type(), RecordType::DNSKEY);
}

#[tokio::test]
async fn doh_roundtrip_over_https() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\ndohelloworld"})),
        )
        .mount(&tgi)
        .await;
    let port = 15361;
    let addr = format!("127.0.0.1:{port}");
    let doh = "127.0.0.1:15581";
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--doh-address",
        doh,
        // hickory checks :authority against this; cert check is disabled.
        "--dns-hostname",
        "127.0.0.1",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let mut q = Message::new();
    q.set_id(99)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    q.add_query(Query::query(
        Name::from_str("hello.").unwrap(),
        RecordType::TXT,
    ));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let resp_bytes = client
        .post(format!("https://{doh}/dns-query"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(q.to_bytes().unwrap())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let resp = Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.answers().len(), 1);
    assert!(matches!(
        resp.answers()[0].data(),
        Some(hickory_proto::rr::RData::TXT(_))
    ));
}

#[tokio::test]
async fn oversize_qname_refused() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15362;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--max-qname-bytes",
        "20",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "this-name-is-far-too-long.", RecordType::TXT);
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
}

#[tokio::test]
async fn kill_switch_refuses_llm_paths() {
    let tgi = wiremock::MockServer::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let kill = dir.path().join("KILL");
    std::fs::write(&kill, "stop").unwrap();
    let port = 15363;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--kill-file",
        kill.to_str().unwrap(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "hello.", RecordType::TXT);
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
    // Non-LLM paths still served.
    let a = dns_query(&addr, "hello.", RecordType::A);
    assert_eq!(a.response_code(), hickory_proto::op::ResponseCode::NoError);
}

#[tokio::test]
async fn stateless_answer_cached_and_audited() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\ncached-reply"})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let dir = tempfile::TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let port = 15364;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--audit-log",
        audit.to_str().unwrap(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let r1 = dns_query(&addr, "repeat-me.", RecordType::TXT);
    let r2 = dns_query(&addr, "repeat-me.", RecordType::TXT);
    assert_eq!(r1.answers().len(), 1);
    assert_eq!(r2.answers().len(), 1);
    // Audit log has both queries.
    let text = std::fs::read_to_string(&audit).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("cache_hit"));
}

fn dns_update(addr: &str, zone_query: &str, records: Vec<hickory_proto::rr::Record>) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut msg = Message::new();
    msg.set_id(4321)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    msg.add_query(Query::query(
        Name::from_str(zone_query).unwrap(),
        RecordType::SOA,
    ));
    for r in records {
        msg.add_name_server(r);
    }
    sock.send_to(&msg.to_bytes().unwrap(), addr).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    Message::from_bytes(&buf[..n]).unwrap()
}

fn txt_record(owner: &str, ttl: u32, text: &str) -> hickory_proto::rr::Record {
    hickory_proto::rr::Record::from_rdata(
        Name::from_str(owner).unwrap(),
        ttl,
        hickory_proto::rr::RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![text.to_string()])),
    )
}

#[tokio::test]
async fn kv_write_then_read_roundtrip() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15365;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--auth-token",
        "s3cr3t",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // Write without token -> refused.
    let denied = dns_update(
        &addr,
        "dumb.",
        vec![txt_record("mykey._kv.dumb.", 60, "nope")],
    );
    assert_eq!(
        denied.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
    // Write with token (first label of zone query) -> NOERROR.
    let ok = dns_update(
        &addr,
        "s3cr3t.dumb.",
        vec![txt_record("mykey._kv.dumb.", 60, "kv-value-42")],
    );
    assert_eq!(ok.response_code(), hickory_proto::op::ResponseCode::NoError);
    // Read back via getter — no LLM involved.
    let got = dns_query(&addr, "mykey._kv.dumb.", RecordType::TXT);
    assert_eq!(got.answers().len(), 1);
    if let Some(hickory_proto::rr::RData::TXT(t)) = got.answers()[0].data() {
        let joined: String = t
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert_eq!(joined, "kv-value-42");
    } else {
        panic!("expected TXT");
    }
    // Unknown key -> empty NOERROR (never calls LLM).
    let miss = dns_query(&addr, "absent._kv.dumb.", RecordType::TXT);
    assert!(miss.answers().is_empty());
}

#[tokio::test]
async fn memory_fact_reaches_llm_prompt() {
    let tgi = wiremock::MockServer::start().await;
    // Only matches once the memory fact is injected into the prompt.
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::body_string_contains("squirrels"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nnoted"})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let port = 15366;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--auth-token",
        "s3cr3t",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let w = dns_update(
        &addr,
        "s3cr3t.dumb.",
        vec![txt_record("sess7._mem.dumb.", 60, "user likes squirrels")],
    );
    assert_eq!(w.response_code(), hickory_proto::op::ResponseCode::NoError);
    // Session query triggers LLM call whose prompt must contain the fact.
    let resp = dns_query(&addr, "sess7.dumb.", RecordType::TXT);
    assert_eq!(resp.answers().len(), 1);
}

#[tokio::test]
async fn beads_hierarchy_parent_reads_child_facts() {
    let tgi = wiremock::MockServer::start().await;
    // Matches only when BOTH beads' facts reach the prompt.
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::body_string_contains("bead-parent"))
        .and(wiremock::matchers::body_string_contains("bead-child"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nbeaded"})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let port = 15367;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--auth-token",
        "s3cr3t",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // DNS-reversed beads: most-specific label first.
    for (owner, fact) in [
        ("n1.proj9._mem.dumb.", "bead-parent"),
        ("n2.n1.proj9._mem.dumb.", "bead-child"),
    ] {
        let w = dns_update(&addr, "s3cr3t.dumb.", vec![txt_record(owner, 60, fact)]);
        assert_eq!(w.response_code(), hickory_proto::op::ResponseCode::NoError);
    }
    let resp = dns_query(&addr, "n1.proj9.dumb.", RecordType::TXT);
    assert_eq!(resp.answers().len(), 1);
}

#[tokio::test]
async fn blocklist_refuses_matching_prompt() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15369;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--deny-patterns",
        "AKIA[0-9A-Z]{16}",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let bad = dns_query(&addr, "AKIAIOSFODNN7EXAMPLE.evil.", RecordType::TXT);
    assert_eq!(
        bad.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
    let ok = dns_query(&addr, "innocent.", RecordType::TXT);
    assert_eq!(ok.response_code(), hickory_proto::op::ResponseCode::NoError);
}

#[tokio::test]
async fn circuit_breaker_stops_calling_dead_llm() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&tgi)
        .await;
    let port = 15372;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--cb-threshold",
        "2",
        "--cb-cooldown-secs",
        "60",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    for i in 0..4 {
        let r = dns_query(&addr, &format!("q{i}.dead."), RecordType::TXT);
        assert_eq!(r.response_code(), hickory_proto::op::ResponseCode::NoError);
        assert!(r.answers().len() <= 1);
    }
    // Breaker opened after 2 failures: only 2 upstream calls for 4 queries.
    let received = tgi.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
}

#[tokio::test]
async fn openai_backend_serves_stateful_session() {
    let llm = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/chat/completions"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            serde_json::json!({
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "test-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "chat-reply-7"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }),
        ))
        .expect(1)
        .mount(&llm)
        .await;
    let port = 15373;
    let addr = format!("127.0.0.1:{port}");
    // async-openai appends /chat/completions to the base: base includes /v1.
    let base = format!("{}/v1", llm.uri());
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &base,
        "--llm-backend",
        "openai",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "sess9._llm.hi.dumb.", RecordType::TXT);
    assert_eq!(resp.answers().len(), 1);
    if let Some(hickory_proto::rr::RData::TXT(t)) = resp.answers()[0].data() {
        let joined: String = t
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert_eq!(joined, "chat-reply-7");
    } else {
        panic!("expected TXT");
    }
}

#[tokio::test]
async fn fragments_buffer_then_flush_into_prompt() {
    let tgi = wiremock::MockServer::start().await;
    // Matches only when both buffered fragments precede the flush prompt.
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::body_string_contains("alpha beta"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nreassembled"})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let port = 15374;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // Out-of-order parts are buffered (ACK, exactly one LLM call total later).
    let a1 = dns_query(&addr, "sessF._part.1.beta.dumb.", RecordType::TXT);
    let a0 = dns_query(&addr, "sessF._part.0.alpha.dumb.", RecordType::TXT);
    for a in [&a1, &a0] {
        if let Some(hickory_proto::rr::RData::TXT(t)) = a.answers()[0].data() {
            let j: String = t
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect();
            assert!(j.starts_with("ACK"), "expected ACK, got {j}");
        } else {
            panic!("expected TXT ACK");
        }
    }
    // Plain session query flushes buffer in seq order ahead of its prompt.
    let r = dns_query(&addr, "sessF.dumb.", RecordType::TXT);
    assert_eq!(r.answers().len(), 1);
}

#[tokio::test]
async fn paging_serves_full_reply_in_chunks() {
    let tgi = wiremock::MockServer::start().await;
    let full = "B".repeat(600);
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": format!("h1\nh2\n{full}")})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let port = 15375;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let r = dns_query(&addr, "pageSess._llm.start.dumb.", RecordType::TXT);
    assert_eq!(r.answers().len(), 1);
    let mut rebuilt = String::new();
    for n in 0..5 {
        let p = dns_query(&addr, &format!("pageSess._page.{n}.dumb."), RecordType::TXT);
        if p.answers().is_empty() {
            break;
        }
        if let Some(hickory_proto::rr::RData::TXT(t)) = p.answers()[0].data() {
            rebuilt.push_str(
                &t.iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<String>(),
            );
        }
    }
    assert_eq!(rebuilt, full);
}

#[tokio::test]
async fn edns_small_payload_gets_tc_without_answers() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"generated_text": format!("h1\nh2\n{}", "C".repeat(600))}),
        ))
        .mount(&tgi)
        .await;
    let port = 15376;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query_edns_payload(&addr, "big._llm.x.dumb.", RecordType::TXT, false, 128);
    assert!(resp.truncated());
    assert!(resp.answers().is_empty());
    // Generous payload still gets the full answer.
    let full = dns_query(&addr, "big._llm.x.dumb.", RecordType::TXT);
    assert!(!full.truncated());
    assert_eq!(full.answers().len(), 1);
}

#[tokio::test]
async fn smuggle_cname_returns_hex_target() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nABCDEF"})),
        )
        .mount(&tgi)
        .await;
    let port = 15377;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--smuggle-cname",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let resp = dns_query(&addr, "hello.", RecordType::CNAME);
    assert_eq!(resp.answers().len(), 1);
    assert!(matches!(
        resp.answers()[0].data(),
        Some(hickory_proto::rr::RData::CNAME(_))
    ));
}

#[tokio::test]
async fn doq_listener_binds_port() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15378;
    let addr = format!("127.0.0.1:{port}");
    let doq = "127.0.0.1:15535";
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--doq-address",
        doq,
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // Bind-only (no QUIC client wired): rebinding the same UDP port must fail.
    assert!(UdpSocket::bind(doq).is_err(), "DoQ port not bound");
}

#[tokio::test]
async fn rag_context_reaches_llm_prompt() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "brussels-sprouts-fact",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nrag-ok"})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let dir = tempfile::TempDir::new().unwrap();
    let corpus = dir.path().join("corpus.txt");
    std::fs::write(
        &corpus,
        "unrelated line about paint\nthe brussels-sprouts-fact page says water daily\n",
    )
    .unwrap();
    let port = 15379;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
        "--rag-corpus",
        corpus.to_str().unwrap(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    let r = dns_query(
        &addr,
        "how.often.to.water.brussels.sprouts.",
        RecordType::TXT,
    );
    assert_eq!(r.answers().len(), 1);
}

#[tokio::test]
async fn explicit_llm_form_asks_with_short_identity() {
    let tgi = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "capital of france",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"generated_text": "h1\nh2\nParis"})),
        )
        .expect(1)
        .mount(&tgi)
        .await;
    let port = 15382;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // Identity stays short; prompt text rides after the feature.
    let r = dns_query(
        &addr,
        "f9._llm.what.is.the.capital.of.france.dumb.",
        RecordType::TXT,
    );
    assert_eq!(r.answers().len(), 1);
    // History follows the short id: paging key is short too.
    let p = dns_query(&addr, "f9._page.0.dumb.", RecordType::TXT);
    assert_eq!(p.answers().len(), 1);
}

#[tokio::test]
async fn bare_new_session_answers_empty_without_llm_call() {
    let tgi = wiremock::MockServer::start().await;
    let port = 15383;
    let addr = format!("127.0.0.1:{port}");
    let _server = ServerGuard::spawn(&[
        "--dns-listening-address",
        &addr,
        "--llm-endpoint",
        &tgi.uri(),
    ]);
    std::thread::sleep(Duration::from_secs(1));
    // No text, no buffer, no history: empty answer, zero model calls.
    let r = dns_query(&addr, "brandnew.dumb.", RecordType::TXT);
    assert_eq!(r.response_code(), hickory_proto::op::ResponseCode::NoError);
    assert!(r.answers().is_empty());
    let received = tgi.received_requests().await.unwrap();
    assert!(received.is_empty());
}

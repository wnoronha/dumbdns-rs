//! Append-only JSONL audit log (one line per DNS query).
//!
//! Opened per write (no long-held file lock); disabled when path is empty.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuditEntry<'a> {
    pub ts_unix: u64,
    pub client: &'a str,
    pub transport: &'a str,
    pub qtype: &'a str,
    pub qname: &'a str,
    pub result: &'a str,
    pub reply_bytes: usize,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort append; never fails the query path.
pub fn append(path: &str, entry: &AuditEntry<'_>) {
    if path.is_empty() {
        return;
    }
    let Ok(line) = serde_json::to_string(entry) else {
        return;
    };
    use std::io::Write;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(f, "{line}");
}

pub fn entry<'a>(
    client: &'a str,
    transport: &'a str,
    qtype: &'a str,
    qname: &'a str,
    result: &'a str,
    reply_bytes: usize,
) -> AuditEntry<'a> {
    AuditEntry {
        ts_unix: now_unix(),
        client,
        transport,
        qtype,
        qname,
        result,
        reply_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_jsonl_line() {
        let dir = std::env::temp_dir().join("dumbdns_audit_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().unwrap();
        append(p, &entry("1.2.3.4", "UDP", "TXT", "x.", "ok", 10));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"qtype\":\"TXT\""));
        // Disabled path is a no-op.
        append("", &entry("a", "b", "c", "d", "e", 0));
    }
}

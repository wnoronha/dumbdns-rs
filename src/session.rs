//! SQLite-backed multi-turn session store (`sessions` table).
//!
//! Histories are JSON `(role, content)` pairs capped at 40 entries
//! (token budget), with idle-TTL expiry and LRU eviction at `max_sessions`.
use rusqlite::{params, Connection};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// SQLite-backed multi-turn session store.
pub struct SessionStore {
    conn: Mutex<Connection>,
    max_sessions: usize,
    ttl_secs: i64,
}

impl SessionStore {
    pub fn open_in_memory(max_sessions: usize, ttl_secs: u64) -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let s = Self {
            conn: Mutex::new(conn),
            max_sessions,
            ttl_secs: ttl_secs as i64,
        };
        s.init()?;
        Ok(s)
    }

    #[allow(dead_code)]
    pub fn open_file(path: &str, max_sessions: usize, ttl_secs: u64) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let s = Self {
            conn: Mutex::new(conn),
            max_sessions,
            ttl_secs: ttl_secs as i64,
        };
        s.init()?;
        Ok(s)
    }

    fn init(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions(
               id TEXT PRIMARY KEY, history TEXT NOT NULL,
               created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS kv(
               key TEXT PRIMARY KEY, value TEXT NOT NULL,
               updated_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS last_reply(
               session TEXT PRIMARY KEY, reply TEXT NOT NULL,
               updated_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS fragments(
               session TEXT NOT NULL, seq INTEGER NOT NULL, chunk TEXT NOT NULL,
               updated_at INTEGER NOT NULL,
               PRIMARY KEY (session, seq));",
        )?;
        Ok(())
    }

    /// Key-value put with size caps. Returns stored byte count.
    pub fn kv_put(&self, key: &str, value: &str, max_value_bytes: usize) -> anyhow::Result<usize> {
        if key.len() > 255 {
            anyhow::bail!("key too long");
        }
        let mut v = value.to_string();
        if v.len() > max_value_bytes {
            let mut end = max_value_bytes;
            while !v.is_char_boundary(end) {
                end -= 1;
            }
            v.truncate(end);
        }
        let n = v.len();
        let t = now();
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO kv(key,value,updated_at) VALUES(?1,?2,?3)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            params![key, v, t],
        )?;
        let cap = (self.max_sessions.max(1) * 10) as i64;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0))?;
        if count > cap {
            conn.execute(
                "DELETE FROM kv WHERE key IN
                 (SELECT key FROM kv ORDER BY updated_at ASC LIMIT ?1)",
                params![count - cap],
            )?;
        }
        Ok(n)
    }

    pub fn kv_get(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT value FROM kv WHERE key=?1", params![key], |r| {
            r.get(0)
        })
        .ok()
    }

    /// Buffer one prompt fragment; at most 32 buffered per session.
    pub fn frag_store(&self, session: &str, seq: u32, chunk: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO fragments(session,seq,chunk,updated_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(session,seq) DO UPDATE SET chunk=excluded.chunk, updated_at=excluded.updated_at",
            params![session, seq, chunk, now()],
        )?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM fragments WHERE session=?1",
            params![session],
            |r| r.get(0),
        )?;
        if count > 32 {
            conn.execute(
                "DELETE FROM fragments WHERE session=?1 AND seq NOT IN
                 (SELECT seq FROM fragments WHERE session=?1 ORDER BY seq DESC LIMIT 32)",
                params![session],
            )?;
        }
        Ok(())
    }

    /// Take all buffered fragments in seq order (clears the buffer).
    pub fn frag_take(&self, session: &str) -> Vec<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<(u32, String)> = conn
            .prepare("SELECT seq, chunk FROM fragments WHERE session=?1 ORDER BY seq ASC")
            .map(|mut st| {
                st.query_map(params![session], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map(|m| m.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let _ = conn.execute("DELETE FROM fragments WHERE session=?1", params![session]);
        rows.into_iter().map(|(_, c)| c).collect()
    }

    /// Store the full (pre-truncation) reply for `more.N` paging, capped at 8KiB.
    pub fn reply_store(&self, session: &str, reply: &str) {
        let mut v = reply.to_string();
        if v.len() > 8192 {
            let mut end = 8192;
            while !v.is_char_boundary(end) {
                end -= 1;
            }
            v.truncate(end);
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO last_reply(session,reply,updated_at) VALUES(?1,?2,?3)
             ON CONFLICT(session) DO UPDATE SET reply=excluded.reply, updated_at=excluded.updated_at",
            params![session, v, now()],
        );
    }

    pub fn reply_get(&self, session: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT reply FROM last_reply WHERE session=?1 AND updated_at >= ?2",
            params![session, now() - self.ttl_secs],
            |r| r.get(0),
        )
        .ok()
    }

    /// Stored memory facts for a session (role == "memory"), oldest first.
    ///
    /// Beads: also includes facts from child beads — any session id of which
    /// `id` is a dot-suffix (e.g. read `n1.proj` pulls `n2.n1.proj` too),
    /// most-general first. Expired rows are skipped.
    pub fn memories(&self, id: &str, max: usize) -> Vec<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(rows) = conn
            .prepare("SELECT id, history FROM sessions WHERE updated_at >= ?1")
            .map(|mut st| {
                st.query_map(params![now() - self.ttl_secs], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map(|mapped| mapped.filter_map(|r| r.ok()).collect::<Vec<_>>())
            })
        else {
            return vec![];
        };
        let rows = rows.unwrap_or_default();
        let mut with_depth: Vec<(usize, usize, String)> = vec![];
        for (order, (sid, hist)) in rows.iter().enumerate() {
            let rel = sid == id || sid.ends_with(&format!(".{id}"));
            if !rel {
                continue;
            }
            let depth = sid.matches('.').count();
            let hist: Vec<(String, String)> = serde_json::from_str(hist).unwrap_or_default();
            for (role, content) in hist {
                if role == "memory" {
                    with_depth.push((depth, order, content));
                }
            }
        }
        with_depth.sort_by_key(|(d, o, _)| (*d, *o));
        with_depth
            .into_iter()
            .map(|(_, _, c)| c)
            .take(max)
            .collect()
    }

    pub fn get(&self, id: &str) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let hist: String = conn
            .query_row(
                "SELECT history FROM sessions WHERE id=?1 AND updated_at >= ?2",
                params![id, now() - self.ttl_secs],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "[]".to_string());
        Ok(serde_json::from_str(&hist).unwrap_or_default())
    }

    pub fn append(&self, id: &str, role: &str, content: &str) -> anyhow::Result<()> {
        let mut hist = self.get(id)?;
        hist.push((role.to_string(), content.to_string()));
        // Token budget: keep last 20 turns max.
        if hist.len() > 40 {
            hist = hist.split_off(hist.len() - 40);
        }
        let json = serde_json::to_string(&hist)?;
        let t = now();
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO sessions(id,history,created_at,updated_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(id) DO UPDATE SET history=excluded.history, updated_at=excluded.updated_at",
            params![id, json, t, t],
        )?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        if count as usize > self.max_sessions {
            conn.execute(
                "DELETE FROM sessions WHERE id IN
                 (SELECT id FROM sessions ORDER BY updated_at ASC LIMIT ?1)",
                params![count - self.max_sessions as i64],
            )?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn reset(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM sessions WHERE id=?1", params![id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_lru_bound() {
        let s = SessionStore::open_in_memory(2, 600).unwrap();
        s.append("a", "user", "hi").unwrap();
        s.append("a", "assistant", "hello").unwrap();
        assert_eq!(s.get("a").unwrap().len(), 2);
        s.append("b", "user", "x").unwrap();
        s.append("c", "user", "y").unwrap();
        // max 2 sessions: oldest evicted
        assert!(s.get("a").unwrap().is_empty());
    }

    #[test]
    fn hierarchical_memories_pull_child_beads() {
        let s = SessionStore::open_in_memory(10, 600).unwrap();
        s.append("n1.proj", "memory", "parent fact").unwrap();
        s.append("n2.n1.proj", "memory", "child fact").unwrap();
        s.append("other", "memory", "unrelated").unwrap();
        let got = s.memories("n1.proj", 10);
        assert_eq!(got, vec!["parent fact", "child fact"]);
        assert!(s.memories("proj", 10).len() >= 2);
        assert!(s.memories("other", 10) == vec!["unrelated"]);
    }

    #[test]
    fn fragments_roundtrip_in_seq_order() {
        let s = SessionStore::open_in_memory(10, 600).unwrap();
        s.frag_store("a", 1, "world").unwrap();
        s.frag_store("a", 0, "hello").unwrap();
        assert_eq!(s.frag_take("a"), vec!["hello", "world"]);
        assert!(s.frag_take("a").is_empty());
    }

    #[test]
    fn expired_sessions_read_empty() {
        let s = SessionStore::open_in_memory(10, 0).unwrap();
        s.append("z", "user", "hi").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(s.get("z").unwrap().is_empty());
    }
}

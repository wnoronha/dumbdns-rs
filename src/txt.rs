/// Clean + chunk LLM text into DNS TXT strings (each <= 255 bytes, char-boundary safe).
///
/// Go parity: strip first two lines of TGI response, remove `<|assistant|>`.
pub fn clean_response(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let joined = if lines.len() > 2 {
        lines[2..].join("\n")
    } else {
        raw.to_string()
    };
    joined.replace("<|assistant|>", "")
}

/// Truncate to `max` bytes on a char boundary; returns (text, was_truncated).
pub fn truncate_bytes(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}…[truncated]", &s[..end]), true)
}

/// Split into <=255-byte chunks without splitting a UTF-8 char.
pub fn chunk_txt(s: &str) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    let mut parts = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + 255).min(s.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(s[start..end].to_string());
        start = end;
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_first_two_lines_and_role_token() {
        let raw = "header1\nheader2\n<|assistant|>hello world";
        assert_eq!(clean_response(raw), "hello world");
    }

    #[test]
    fn short_responses_untouched_apart_from_token() {
        assert_eq!(clean_response("<|assistant|>hi"), "hi");
    }

    #[test]
    fn chunks_respect_255_byte_limit_and_roundtrip() {
        let s = "a".repeat(600);
        let parts = chunk_txt(&s);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len() <= 255));
        assert_eq!(parts.concat(), s);
    }

    #[test]
    fn chunks_never_split_utf8_char() {
        let s = "é".repeat(200); // 400 bytes
        let parts = chunk_txt(&s);
        assert!(parts.iter().all(|p| p.len() <= 255));
        assert_eq!(parts.concat(), s);
        for p in &parts {
            assert!(std::str::from_utf8(p.as_bytes()).is_ok());
        }
    }
}

#[cfg(test)]
mod truncate_tests {
    use super::truncate_bytes;

    #[test]
    fn truncates_on_char_boundary_with_sentinel() {
        let (t, cut) = truncate_bytes(&"a".repeat(100), 10);
        assert!(cut);
        assert!(t.ends_with("[truncated]"));
        let (same, cut2) = truncate_bytes("hi", 10);
        assert!(!cut2 && same == "hi");
        let (u, _) = truncate_bytes(&"é".repeat(10), 5);
        assert!(std::str::from_utf8(u.as_bytes()).is_ok());
    }
}

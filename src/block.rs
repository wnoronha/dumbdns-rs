//! Exfil-pattern blocklist: deny regexes matched against prompts and values.
//!
//! Patterns come from `--deny-patterns` (comma-separated). A match refuses
//! the query before any LLM call or stored write.

pub struct Blocklist {
    patterns: Vec<regex::Regex>,
}

impl Blocklist {
    pub fn compile(csv: &str) -> anyhow::Result<Self> {
        let mut patterns = Vec::new();
        for pat in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            // DNS lowercases QNAMEs, so case-sensitive exfil shapes (PEM
            // headers, AKIA keys) would never match: force case-insensitive.
            let pat = format!("(?i){pat}");
            patterns.push(
                regex::Regex::new(&pat)
                    .map_err(|e| anyhow::anyhow!("bad deny pattern {pat:?}: {e}"))?,
            );
        }
        Ok(Self { patterns })
    }

    pub fn blocked(&self, text: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(text))
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_pem_and_aws_key_shapes() {
        let b = Blocklist::compile("BEGIN PRIVATE KEY,AKIA[0-9A-Z]{16}").unwrap();
        assert!(b.blocked("x BEGIN PRIVATE KEY y"));
        assert!(b.blocked("AKIAIOSFODNN7EXAMPLE"));
        assert!(!b.blocked("hello world"));
        assert!(Blocklist::compile("").unwrap().is_empty());
    }

    #[test]
    fn bad_pattern_errors() {
        assert!(Blocklist::compile("([unclosed").is_err());
    }
}

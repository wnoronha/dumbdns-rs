//! QNAME codec: `{id}[._feature[.args…]].<zone>` splitting + base32 helpers.
//!
//! DNS limits: label <= 63B, name <= 255B. Rule: the first underscore label
//! is the feature boundary; everything left of it is the id path (dots kept
//! for beads); everything right of it (before the zone) are feature args.
//! Names without underscore labels are sessions (dotted = hierarchical) or,
//! outside our zone, raw prompts. Data labels never collide: ids must not
//! start with `_`, and `_`-features are reserved infrastructure.

/// Split an in-zone name into `(id_path, feature, args)`.
///
/// Returns None outside our zone. `feature` is None for plain sessions;
/// otherwise it is the underscore label (`_kv`, `_mem`, `_page`, `_part`,
/// `_c2`, …) and `args` are the labels between it and the zone.
pub fn split_infra(name: &str, zone: &str) -> Option<(String, Option<String>, Vec<String>)> {
    let name = name.trim_end_matches('.').to_lowercase();
    let zone = zone.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let zlabels: Vec<&str> = zone.split('.').collect();
    if labels.len() < zlabels.len() {
        return None;
    }
    let (prefix, tail) = labels.split_at(labels.len() - zlabels.len());
    if tail != zlabels.as_slice() || prefix.is_empty() {
        return None;
    }
    match prefix.iter().position(|l| l.starts_with('_')) {
        None => Some((prefix.join("."), None, vec![])),
        Some(i) => {
            let id = prefix[..i].join(".");
            if id.is_empty() || id.starts_with('_') {
                return None;
            }
            Some((
                id,
                Some(prefix[i].to_string()),
                prefix[i + 1..].iter().map(|s| s.to_string()).collect(),
            ))
        }
    }
}

#[allow(dead_code)]
/// Encode arbitrary bytes into lowercase base32 labels of <=63 chars.
pub fn encode_labels(data: &[u8]) -> Vec<String> {
    let s = base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase();
    s.as_bytes()
        .chunks(63)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

#[allow(dead_code)]
pub fn decode_labels(labels: &[String]) -> anyhow::Result<Vec<u8>> {
    let joined = labels.concat().to_uppercase();
    base32::decode(base32::Alphabet::RFC4648 { padding: false }, &joined)
        .ok_or_else(|| anyhow::anyhow!("invalid base32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_dotted_ids_split_cleanly() {
        assert_eq!(
            split_infra("abc123.dumb.", "dumb."),
            Some(("abc123".into(), None, vec![]))
        );
        assert_eq!(
            split_infra("n3.n2.n1.proj-ab12.dumb.", "dumb."),
            Some(("n3.n2.n1.proj-ab12".into(), None, vec![]))
        );
    }

    #[test]
    fn infra_split_finds_feature_boundary() {
        assert_eq!(
            split_infra("n1.proj._mem.dumb.", "dumb."),
            Some(("n1.proj".into(), Some("_mem".into()), vec![]))
        );
        assert_eq!(
            split_infra("s._page.2.dumb.", "dumb."),
            Some(("s".into(), Some("_page".into()), vec!["2".into()]))
        );
        assert_eq!(
            split_infra("s._part.0.abcd.dumb.", "dumb."),
            Some((
                "s".into(),
                Some("_part".into()),
                vec!["0".into(), "abcd".into()]
            ))
        );
        // `mem` without underscore is just a session label, not a feature.
        assert_eq!(
            split_infra("x.mem.dumb.", "dumb."),
            Some(("x.mem".into(), None, vec![]))
        );
    }

    #[test]
    fn rejects_foreign_zone() {
        assert!(split_infra("x.example.com.", "dumb.").is_none());
    }

    #[test]
    fn rejects_empty_id() {
        assert!(split_infra("_mem.dumb.", "dumb.").is_none());
        assert!(split_infra("dumb.", "dumb.").is_none());
    }
}

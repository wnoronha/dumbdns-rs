/// Statistical retrieval (TF-IDF cosine) over a line-per-doc corpus file.
///
/// Deterministic, offline and dependency-free. A real embedding backend
/// (e.g. `fastembed` + sqlite-vss) is tracked future work; TF-IDF already
/// beats raw keyword overlap on paraphrase and multi-term queries.
fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 1)
        .map(|w| w.to_lowercase())
        .collect()
}

fn tfidf(corpus_toks: &[Vec<String>], query_toks: &[String], top_k: usize) -> Vec<usize> {
    let n = corpus_toks.len() as f64;
    // document frequency per term over corpus + query vocabulary
    use std::collections::{HashMap, HashSet};
    let mut df: HashMap<&str, usize> = HashMap::new();
    for doc in corpus_toks {
        for t in doc.iter().collect::<HashSet<_>>() {
            *df.entry(t).or_insert(0) += 1;
        }
    }
    let idf = |t: &str| ((n + 1.0) / (df.get(t).copied().unwrap_or(0) as f64 + 1.0)).ln() + 1.0;
    // query vector
    let mut qtf: HashMap<&str, usize> = HashMap::new();
    for t in query_toks {
        *qtf.entry(t).or_insert(0) += 1;
    }
    let qnorm: f64 = qtf
        .iter()
        .map(|(t, c)| {
            let w = (*c as f64) * idf(t);
            w * w
        })
        .sum::<f64>()
        .sqrt();
    if qnorm == 0.0 {
        return vec![];
    }
    let mut scored: Vec<(usize, f64)> = Vec::new();
    for (i, doc) in corpus_toks.iter().enumerate() {
        let mut dtf: HashMap<&str, usize> = HashMap::new();
        for t in doc {
            *dtf.entry(t).or_insert(0) += 1;
        }
        let mut dot = 0.0;
        let mut dnorm2 = 0.0;
        for (t, c) in &dtf {
            let w = (*c as f64) * idf(t);
            dnorm2 += w * w;
            if let Some(qc) = qtf.get(t) {
                dot += w * (*qc as f64) * idf(t);
            }
        }
        let denom = dnorm2.sqrt() * qnorm;
        if denom > 0.0 && dot > 0.0 {
            scored.push((i, dot / denom));
        }
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().take(top_k).map(|(i, _)| i).collect()
}

/// Rank corpus docs for `query`, returning the top-k documents.
pub fn retrieve(corpus: &[String], query: &str, top_k: usize) -> Vec<String> {
    let ctoks: Vec<Vec<String>> = corpus.iter().map(|d| tokens(d)).collect();
    tfidf(&ctoks, &tokens(query), top_k)
        .into_iter()
        .map(|i| corpus[i].clone())
        .collect()
}

pub fn load_corpus(path: &str) -> Vec<String> {
    if path.is_empty() {
        return vec![];
    }
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_relevant_doc_first() {
        let corpus = vec![
            "cats are great companions".into(),
            "dogs bark loudly at night".into(),
            "quantum field theory primer".into(),
        ];
        let out = retrieve(&corpus, "tell me about barking dogs", 1);
        assert_eq!(out, vec!["dogs bark loudly at night"]);
    }

    #[test]
    fn multi_term_query_prefers_best_overlap() {
        let corpus = vec!["red apple".into(), "red apple pie recipe".into()];
        let out = retrieve(&corpus, "apple pie", 2);
        assert_eq!(out[0], "red apple pie recipe");
    }

    #[test]
    fn no_overlap_returns_empty() {
        let corpus = vec!["hello world".into()];
        assert!(retrieve(&corpus, "xyzzy qqq", 3).is_empty());
    }

    #[test]
    fn empty_path_gives_empty_corpus() {
        assert!(load_corpus("").is_empty());
    }
}

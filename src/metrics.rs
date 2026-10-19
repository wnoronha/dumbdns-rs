//! Prometheus metrics: query counts by (qtype, result) and LLM latency.
//!
//! NOTE: the registry is built in `main` but not yet served over HTTP;
//! wiring `/metrics` is tracked follow-up work.
use prometheus::{HistogramVec, IntCounterVec, Registry};

pub struct Metrics {
    pub queries: IntCounterVec,
    pub llm_latency: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let queries = IntCounterVec::new(
            prometheus::Opts::new("dumbdns_queries_total", "DNS queries by type/result"),
            &["qtype", "result"],
        )?;
        let llm_latency = HistogramVec::new(
            prometheus::HistogramOpts::new("dumbdns_llm_seconds", "LLM latency"),
            &["backend"],
        )?;
        registry.register(Box::new(queries.clone()))?;
        registry.register(Box::new(llm_latency.clone()))?;
        Ok(Self {
            queries,
            llm_latency,
        })
    }
}

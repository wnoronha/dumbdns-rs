//! dumbdns-rs binary: binds UDP+TCP always, DoT/DoH/DoQ when configured.
mod audit;
mod block;
mod codec;
mod config;
mod dns;
mod dnssec;
mod metrics;
mod rag;
mod session;
mod tgi;
mod tls;
mod txt;

use anyhow::Result;
use clap::Parser;
use config::Config;
use hickory_server::ServerFuture;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = Config::parse();
    // Precedence: CLI > env > file > built-in defaults.
    if let Err(e) = cfg.merge_file() {
        eprintln!("warning: ignoring config file: {e:#}");
    }
    tracing_subscriber::fmt()
        .with_env_filter(if cfg.verbose { "debug" } else { "info" })
        .init();

    let registry = prometheus::Registry::new();
    let metrics = Arc::new(metrics::Metrics::new(&registry)?);
    if !cfg.metrics_address.is_empty() {
        let addr = cfg.metrics_address.clone();
        let registry = registry.clone();
        tokio::spawn(async move { serve_metrics(&addr, &registry).await });
    }
    let handler = dns::DumbDnsHandler::new(cfg.clone(), Some(metrics))?;
    let mut server = ServerFuture::new(handler);

    let addr: std::net::SocketAddr = cfg.dns_listening_address.parse()?;
    server.register_socket(tokio::net::UdpSocket::bind(addr).await?);
    server.register_listener(
        tokio::net::TcpListener::bind(addr).await?,
        std::time::Duration::from_secs(5),
    );
    tracing::info!(%addr, "dumbdns-rs serving UDP+TCP");

    // DoT / DoH / DoQ share one TLS identity (files or ephemeral self-signed).
    if !cfg.dot_address.is_empty() || !cfg.doh_address.is_empty() || !cfg.doq_address.is_empty() {
        let (certs, key) = tls::load_identity(&cfg.tls_cert, &cfg.tls_key, &cfg.dns_hostname)?;
        if !cfg.dot_address.is_empty() {
            let dot: std::net::SocketAddr = cfg.dot_address.parse()?;
            server.register_tls_listener(
                tokio::net::TcpListener::bind(dot).await?,
                std::time::Duration::from_secs(5),
                (certs.clone(), rustls::PrivateKey(key.0.clone())),
            )?;
            tracing::info!(%dot, "DoT enabled");
        }
        if !cfg.doh_address.is_empty() {
            let doh: std::net::SocketAddr = cfg.doh_address.parse()?;
            server.register_https_listener(
                tokio::net::TcpListener::bind(doh).await?,
                std::time::Duration::from_secs(5),
                (certs.clone(), rustls::PrivateKey(key.0.clone())),
                Some(cfg.dns_hostname.clone()),
            )?;
            tracing::info!(%doh, "DoH enabled");
        }
        if !cfg.doq_address.is_empty() {
            let doq: std::net::SocketAddr = cfg.doq_address.parse()?;
            server.register_quic_listener(
                tokio::net::UdpSocket::bind(doq).await?,
                std::time::Duration::from_secs(5),
                (certs, rustls::PrivateKey(key.0)),
                Some(cfg.dns_hostname.clone()),
            )?;
            tracing::info!(%doq, "DoQ enabled");
        }
    }

    server.block_until_done().await?;
    Ok(())
}

/// Minimal HTTP server for `GET /metrics` (Prometheus text exposition).
async fn serve_metrics(addr: &str, registry: &prometheus::Registry) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("metrics listener {addr} failed: {e:#}");
            return;
        }
    };
    tracing::info!(addr, "metrics enabled");
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let mut buf = [0u8; 1024];
        let Ok(_) = stream.read(&mut buf).await else {
            continue;
        };
        let body = {
            use prometheus::Encoder;
            let mut b = Vec::new();
            let enc = prometheus::TextEncoder::new();
            if enc.encode(&registry.gather(), &mut b).is_err() {
                continue;
            }
            b
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(&body).await;
    }
}

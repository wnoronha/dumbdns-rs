//! TLS identity for DoT / DoH / DoQ.
//!
//! Prefers user-supplied PEM files; falls back to an ephemeral self-signed
//! certificate for `hostname` (good for tests, NOT for production clients
//! unless they pin the fingerprint).
//! Original: PEM files or ephemeral self-signed.

pub type CertChain = (Vec<rustls::Certificate>, rustls::PrivateKey);

pub fn load_identity(cert_file: &str, key_file: &str, hostname: &str) -> anyhow::Result<CertChain> {
    if !cert_file.is_empty() && !key_file.is_empty() {
        let certs = load_certs(cert_file)?;
        let key = load_key(key_file)?;
        return Ok((certs, key));
    }
    self_signed(hostname)
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::Certificate>> {
    let mut rdr = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut out = Vec::new();
    for c in rustls_pemfile::certs(&mut rdr) {
        let c = c.map_err(|e| anyhow::anyhow!("read certs {path}: {e}"))?;
        out.push(rustls::Certificate(c.to_vec()));
    }
    if out.is_empty() {
        anyhow::bail!("no certs in {path}");
    }
    Ok(out)
}

fn load_key(path: &str) -> anyhow::Result<rustls::PrivateKey> {
    let data = std::fs::read(path)?;
    // Try PKCS8 / PKCS1 / SEC1 PEM markers directly.
    let pem = String::from_utf8_lossy(&data);
    if pem.contains("PRIVATE KEY") {
        use base64::Engine;
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| anyhow::anyhow!("invalid base64 in {path}: {e}"))?;
        return Ok(rustls::PrivateKey(der));
    }
    Ok(rustls::PrivateKey(data))
}

fn self_signed(hostname: &str) -> anyhow::Result<CertChain> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
    let cert_der = cert.der().to_vec();
    let key_der = signing_key.serialize_der();
    Ok((
        vec![rustls::Certificate(cert_der)],
        rustls::PrivateKey(key_der),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_identity_loads() {
        let (certs, key) = load_identity("", "", "dumb.local").unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!key.0.is_empty());
    }
}

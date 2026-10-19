//! DNSSEC zone signing (ED25519, ring): DNSKEY serving + RRSIG synthesis.

use hickory_proto::rr::dnssec::rdata::RRSIG;
use hickory_proto::rr::dnssec::KeyPair;
use hickory_proto::rr::dnssec::{Algorithm, SigSigner};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct ZoneSigner {
    pub signer: SigSigner,
    pub zone: Name,
    pub ttl: u32,
    dnskey: hickory_proto::rr::dnssec::rdata::DNSKEY,
}

impl ZoneSigner {
    pub fn load(key_pem_file: &str, zone: &str) -> anyhow::Result<Self> {
        let pem = std::fs::read(key_pem_file)?;
        let key_pair = parse_ed25519_pkcs8(&pem)?;
        let keypair = KeyPair::from_ed25519(key_pair);
        let dnskey = keypair.to_dnskey(Algorithm::ED25519)?;
        let zone_name = Name::from_str(zone)?;
        let signer = SigSigner::dnssec(
            dnskey.clone(),
            keypair,
            zone_name.clone(),
            Duration::from_secs(7 * 24 * 3600),
        );
        Ok(Self {
            signer,
            zone: zone_name,
            ttl: 3600,
            dnskey,
        })
    }

    pub fn dnskey_record(&self) -> Record {
        Record::from_rdata(
            self.zone.clone(),
            self.ttl,
            RData::DNSSEC(hickory_proto::rr::dnssec::rdata::DNSSECRData::DNSKEY(
                self.dnskey.clone(),
            )),
        )
    }

    /// Sign an RRset, returning the RRSIG record (RFC 4035 §8).
    pub fn sign_rrset(&self, records: &[Record]) -> anyhow::Result<Record> {
        let first = records
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty rrset"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        let inception = now - 3600;
        let expiration = now + self.signer.sig_duration().as_secs() as u32;
        let key_tag = self.signer.calculate_key_tag()?;
        let tbs = hickory_proto::rr::dnssec::tbs::rrset_tbs(
            first.name(),
            first.dns_class(),
            first.name().num_labels(),
            first.record_type(),
            Algorithm::ED25519,
            first.ttl(),
            expiration,
            inception,
            key_tag,
            &self.zone,
            records,
        )?;
        let sig = self.signer.sign(&tbs)?;
        let rrsig = RRSIG::new(
            first.record_type(),
            Algorithm::ED25519,
            first.name().num_labels(),
            first.ttl(),
            expiration,
            inception,
            key_tag,
            self.zone.clone(),
            sig,
        );
        Ok(Record::from_rdata(
            first.name().clone(),
            first.ttl(),
            RData::DNSSEC(hickory_proto::rr::dnssec::rdata::DNSSECRData::RRSIG(rrsig)),
        ))
    }

    #[allow(dead_code)]
    pub fn key_tag(&self) -> u16 {
        self.signer.calculate_key_tag().unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn dns_class() -> DNSClass {
        DNSClass::IN
    }

    #[allow(dead_code)]
    pub fn covered() -> RecordType {
        RecordType::TXT
    }
}

fn parse_ed25519_pkcs8(pem: &[u8]) -> anyhow::Result<ring::signature::Ed25519KeyPair> {
    // Accept PEM ("-----BEGIN PRIVATE KEY-----") or raw DER.
    let der: Vec<u8> = if pem.starts_with(b"-----") {
        use base64::Engine;
        let s = std::str::from_utf8(pem)?;
        let b64: String = s
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| anyhow::anyhow!("invalid base64 in key: {e}"))?
    } else {
        pem.to_vec()
    };
    ring::signature::Ed25519KeyPair::from_pkcs8(&der)
        .map_err(|e| anyhow::anyhow!("parse ed25519 pkcs8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::dnssec::Private;

    #[test]
    fn selftest_sign_roundtrip() {
        // Generate an ED25519 key via ring docs, sign a TXT rrset, verify RRSIG fields.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let keypair = KeyPair::<Private>::from_ed25519(kp);
        let dnskey = keypair.to_dnskey(Algorithm::ED25519).unwrap();
        let zone = Name::from_str("dumb.").unwrap();
        let signer = SigSigner::dnssec(
            dnskey.clone(),
            keypair,
            zone.clone(),
            Duration::from_secs(86400),
        );
        let zs = ZoneSigner {
            signer,
            zone,
            ttl: 3600,
            dnskey,
        };
        let rec = Record::from_rdata(
            Name::from_str("x.dumb.").unwrap(),
            3600,
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["hi".to_string()])),
        );
        let sig = zs.sign_rrset(std::slice::from_ref(&rec)).unwrap();
        assert_eq!(sig.record_type(), RecordType::RRSIG);
        let _ = zs.key_tag();
    }
}

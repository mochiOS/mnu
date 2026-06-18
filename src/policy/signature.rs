use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use spin::Mutex;

const DOMAIN: &[u8] = b"mnu-signature-v1\0";
const SIGNATURE_DB_PATH: &str = "/signature.db";

#[derive(Clone)]
struct SignatureRecord {
    path: String,
    digest: [u8; 32],
    signature: [u8; 64],
}

struct SignatureDatabase {
    verifying_key: VerifyingKey,
    records: Vec<SignatureRecord>,
}

static SIGNATURE_DB: Mutex<Option<SignatureDatabase>> = Mutex::new(None);

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let mut idx = 0usize;
    while idx < N {
        let hi = hex_val(bytes[idx * 2])?;
        let lo = hex_val(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
        idx += 1;
    }
    Some(out)
}

fn parse_db(bytes: &[u8]) -> Option<SignatureDatabase> {
    let text = str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?.trim();
    if header != "mnu-signature-db v1" {
        return None;
    }

    let pubkey_line = lines.next()?.trim();
    let pubkey_hex = pubkey_line.strip_prefix("pubkey ")?;
    let pubkey = decode_hex::<32>(pubkey_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey).ok()?;

    let mut records = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("record ") else {
            return None;
        };
        let mut parts = rest.split_whitespace();
        let path = parts.next()?.to_string();
        let digest_hex = parts.next()?;
        let sig_hex = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let digest = decode_hex::<32>(digest_hex)?;
        let signature = decode_hex::<64>(sig_hex)?;
        records.push(SignatureRecord {
            path,
            digest,
            signature,
        });
    }

    Some(SignatureDatabase {
        verifying_key,
        records,
    })
}

fn load_db_from_rootfs() -> bool {
    let Some(bytes) = crate::init::fs::read_rootfs(SIGNATURE_DB_PATH) else {
        crate::warn!("signature: missing {}", SIGNATURE_DB_PATH);
        return false;
    };
    let Some(db) = parse_db(&bytes) else {
        crate::warn!("signature: invalid {}", SIGNATURE_DB_PATH);
        return false;
    };
    *SIGNATURE_DB.lock() = Some(db);
    true
}

fn ensure_loaded() -> bool {
    if SIGNATURE_DB.lock().is_some() {
        true
    } else {
        load_db_from_rootfs()
    }
}

pub fn load_signature_database() -> bool {
    load_db_from_rootfs()
}

pub fn verify_exec(path: &str, data: &[u8]) -> bool {
    if !ensure_loaded() {
        return false;
    }

    let digest = Sha256::digest(data);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest);

    let guard = SIGNATURE_DB.lock();
    let Some(db) = guard.as_ref() else {
        return false;
    };

    for record in &db.records {
        if record.path != path || record.digest != digest_bytes {
            continue;
        }
        let signature = Signature::from_bytes(&record.signature);
        let mut msg = Vec::with_capacity(DOMAIN.len() + path.len() + 1 + digest_bytes.len());
        msg.extend_from_slice(DOMAIN);
        msg.extend_from_slice(path.as_bytes());
        msg.push(0);
        msg.extend_from_slice(&digest_bytes);
        return db.verifying_key.verify_strict(&msg, &signature).is_ok();
    }

    crate::warn!("signature: no matching record for {}", path);
    false
}

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;

use sha2::{Digest, Sha256};
use spin::Mutex;

#[derive(Clone)]
struct SignatureRecord {
    path: String,
    digest: [u8; 32],
}

struct SignatureDatabase {
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
    if header != "mnu-execution-allowlist v1" {
        return None;
    }

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
        if parts.next().is_some() {
            return None;
        }
        let digest = decode_hex::<32>(digest_hex)?;
        records.push(SignatureRecord { path, digest });
    }

    Some(SignatureDatabase { records })
}

fn load_db_from_rootfs() -> bool {
    let Some(allowlist_path) = crate::config::kernel().policy_paths.execution_allowlist() else {
        crate::warn!("execution allowlist path is not configured");
        return false;
    };
    let Some(bytes) = crate::init::fs::read_rootfs(allowlist_path)
        .or_else(|| crate::cext::fs::read_all(allowlist_path))
    else {
        crate::warn!("execution allowlist: missing {}", allowlist_path);
        return false;
    };
    let Some(db) = parse_db(&bytes) else {
        crate::warn!("execution allowlist: invalid {}", allowlist_path);
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

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn verify_exec(path: &str, data: &[u8]) -> bool {
    if !ensure_loaded() {
        return false;
    }

    let digest_bytes = sha256_digest(data);

    let guard = SIGNATURE_DB.lock();
    let Some(db) = guard.as_ref() else {
        return false;
    };

    for record in &db.records {
        if record.path != path || record.digest != digest_bytes {
            continue;
        }
        return true;
    }

    crate::warn!("execution allowlist: no matching record for {}", path);
    false
}

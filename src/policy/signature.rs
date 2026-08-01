use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;

use spin::Mutex;

const EXECUTION_ALLOWLIST_PATH: &str = "/libraries/system/execution.allowlist";

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
    if header != "mochios-execution-allowlist v1" {
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
    let Some(bytes) = crate::init::fs::read_rootfs(EXECUTION_ALLOWLIST_PATH)
        .or_else(|| crate::cext::fs::read_all(EXECUTION_ALLOWLIST_PATH))
    else {
        crate::warn!("execution allowlist: missing {}", EXECUTION_ALLOWLIST_PATH);
        return false;
    };
    let Some(db) = parse_db(&bytes) else {
        crate::warn!("execution allowlist: invalid {}", EXECUTION_ALLOWLIST_PATH);
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

fn rotr32(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h = H0;
    let bit_len = (data.len() as u64) * 8;
    let mut buffer = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    buffer.extend_from_slice(data);
    buffer.push(0x80);
    while (buffer.len() % 64) != 56 {
        buffer.push(0);
    }
    buffer.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in buffer.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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

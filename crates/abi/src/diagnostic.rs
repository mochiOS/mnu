//! Read-only kernel diagnostic history. Cursors are opaque byte positions,
//! never file offsets, process IDs, or service identifiers.

pub const READ_MAX_BYTES: usize = 4096;
pub const RESULT_LEN: usize = 16;
pub const STREAM_AUDIT: u64 = 0;
pub const STREAM_PROCESS_EXIT: u64 = 1;
pub const EXIT_RECORD_LEN: usize = 160;
pub const EXIT_KIND_STATUS: u32 = 1;
pub const EXIT_KIND_EXCEPTION: u32 = 2;

/// Native termination evidence, with no pathname, package or POSIX policy.
/// Zero digest_kind means that no committed image measurement was available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitRecord {
    pub timestamp_ns: u64,
    pub process_id: u64,
    pub thread_id: u64,
    pub image_revision: u64,
    pub exit_code: u64,
    pub kind: u32,
    pub vector: u32,
    pub cause: u32,
    pub error_code: u64,
    pub instruction: u64,
    pub stack_pointer: u64,
    pub address: u64,
    pub image_digest: [u8; 32],
    pub digest_kind: u32,
    pub architecture: u32,
}

impl ExitRecord {
    pub fn to_bytes(self) -> [u8; EXIT_RECORD_LEN] {
        let mut out = [0; EXIT_RECORD_LEN];
        out[..8].copy_from_slice(b"MEXIT\0\0\0");
        out[8..12].copy_from_slice(&1u32.to_le_bytes());
        out[12..16].copy_from_slice(&self.kind.to_le_bytes());
        for (offset, value) in [
            (16, self.timestamp_ns),
            (24, self.process_id),
            (32, self.thread_id),
            (40, self.image_revision),
            (48, self.exit_code),
            (64, self.error_code),
            (72, self.instruction),
            (80, self.stack_pointer),
            (88, self.address),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out[56..60].copy_from_slice(&self.vector.to_le_bytes());
        out[60..64].copy_from_slice(&self.cause.to_le_bytes());
        out[96..128].copy_from_slice(&self.image_digest);
        out[128..132].copy_from_slice(&self.digest_kind.to_le_bytes());
        out[132..136].copy_from_slice(&self.architecture.to_le_bytes());
        out
    }

    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        if input.len() != EXIT_RECORD_LEN
            || &input[..8] != b"MEXIT\0\0\0"
            || input[8..12] != 1u32.to_le_bytes()
            || input[136..].iter().any(|b| *b != 0)
        {
            return None;
        }
        let u64_at = |offset| {
            Some(u64::from_le_bytes(
                input.get(offset..offset + 8)?.try_into().ok()?,
            ))
        };
        let u32_at = |offset| {
            Some(u32::from_le_bytes(
                input.get(offset..offset + 4)?.try_into().ok()?,
            ))
        };
        let kind = u32_at(12)?;
        if !matches!(kind, EXIT_KIND_STATUS | EXIT_KIND_EXCEPTION) {
            return None;
        }
        Some(Self {
            timestamp_ns: u64_at(16)?,
            process_id: u64_at(24)?,
            thread_id: u64_at(32)?,
            image_revision: u64_at(40)?,
            exit_code: u64_at(48)?,
            kind,
            vector: u32_at(56)?,
            cause: u32_at(60)?,
            error_code: u64_at(64)?,
            instruction: u64_at(72)?,
            stack_pointer: u64_at(80)?,
            address: u64_at(88)?,
            image_digest: input[96..128].try_into().ok()?,
            digest_kind: u32_at(128)?,
            architecture: u32_at(132)?,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadResult {
    pub next_cursor: u64,
    pub dropped: u64,
}

impl ReadResult {
    pub fn to_bytes(self) -> [u8; RESULT_LEN] {
        let mut output = [0; RESULT_LEN];
        output[..8].copy_from_slice(&self.next_cursor.to_le_bytes());
        output[8..].copy_from_slice(&self.dropped.to_le_bytes());
        output
    }

    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        if input.len() != RESULT_LEN {
            return None;
        }
        Some(Self {
            next_cursor: u64::from_le_bytes(input[..8].try_into().ok()?),
            dropped: u64::from_le_bytes(input[8..].try_into().ok()?),
        })
    }
}

//! Read-only kernel diagnostic history. Cursors are opaque byte positions,
//! never file offsets, process IDs, or service identifiers.

pub const READ_MAX_BYTES: usize = 4096;
pub const RESULT_LEN: usize = 16;

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

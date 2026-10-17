//! Read-only result record for native asynchronous operations. Read with
//! HandleReadAt; READABLE means terminal, not necessarily successful.
//! This describes mechanism, not any compatibility API's flags or errno.

pub const RECORD_LEN: usize = 16;
pub const PENDING: u64 = 0;
pub const SUCCEEDED: u64 = 1;
pub const FAILED: u64 = 2;

/// Two little-endian u64 fields: phase, then the exact operation error.
/// The error field is zero unless phase is FAILED. FAILED with error zero is
/// distinct from SUCCEEDED; consumers must always inspect phase first.
pub fn encode(result: Option<Result<(), u64>>) -> [u8; RECORD_LEN] {
    let (phase, error) = match result {
        None => (PENDING, 0),
        Some(Ok(())) => (SUCCEEDED, 0),
        Some(Err(error)) => (FAILED, error),
    };
    let mut bytes = [0; RECORD_LEN];
    bytes[..8].copy_from_slice(&phase.to_le_bytes());
    bytes[8..].copy_from_slice(&error.to_le_bytes());
    bytes
}

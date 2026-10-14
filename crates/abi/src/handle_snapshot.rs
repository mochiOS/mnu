//! Immutable Handle-table metadata exposed through HandleReadAt.
//! All fields are little-endian. The 16-byte header contains u32 version,
//! record count, record byte length and zero reserved field. It is followed
//! by `count` HandleInfo records (u32 Handle, zero u32, u64 rights).
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 16;
pub const RECORD_LEN: usize = 16;

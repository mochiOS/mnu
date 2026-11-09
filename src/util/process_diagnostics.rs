//! Fixed native termination history. Readers own their cursor; persistence,
//! names, files and reporting policy are entirely outside this mechanism.
use super::diagnostic_buffer::{ByteRing, CursorError, ReadResult};
use crate::interrupt::spinlock::SpinLock;
use mnu_abi::diagnostic::{ExitRecord, EXIT_RECORD_LEN};

static HISTORY: SpinLock<ByteRing<{ EXIT_RECORD_LEN * 64 }>> = SpinLock::new(ByteRing::new());

#[derive(Clone, Copy, Debug)]
pub struct Exception {
    pub timestamp_ns: u64,
    pub vector: u32,
    pub cause: u32,
    pub error_code: u64,
    pub instruction: u64,
    pub stack_pointer: u64,
    pub address: u64,
}

pub fn publish(record: ExitRecord) {
    let _ = HISTORY.lock().append(&record.to_bytes());
}

pub fn read(cursor: u64, output: &mut [u8]) -> Result<ReadResult, CursorError> {
    HISTORY.lock().read(cursor, output)
}

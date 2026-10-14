//! Bounded diagnostic reads. Authorization is independent of process names,
//! POSIX credentials, filesystem permissions, or a particular consumer.

use super::types::{EACCES, EFAULT, EINVAL};
use crate::util::diagnostic_buffer::CursorError;
use mnu_abi::diagnostic::{READ_MAX_BYTES, RESULT_LEN, ReadResult};

pub fn read(cursor: u64, output: u64, capacity: u64, result: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::DiagnosticsRead,
    ]) {
        return EACCES;
    }
    if capacity > READ_MAX_BYTES as u64 {
        return EINVAL;
    }
    if result == 0
        || !crate::syscall::validate_user_ptr(result, RESULT_LEN as u64)
        || (capacity != 0 && (output == 0 || !crate::syscall::validate_user_ptr(output, capacity)))
    {
        return EFAULT;
    }
    if capacity != 0 {
        // Both ranges were checked, so these bounded additions cannot wrap.
        if output < result + RESULT_LEN as u64 && result < output + capacity {
            return EINVAL;
        }
    }
    let mut bytes = [0; READ_MAX_BYTES];
    let snapshot = match crate::audit::read_cursor(cursor, &mut bytes[..capacity as usize]) {
        Ok(snapshot) => snapshot,
        Err(CursorError::Ahead | CursorError::Exhausted) => return EINVAL,
    };
    if snapshot.bytes != 0 {
        if let Err(error) = crate::syscall::copy_to_user(output, &bytes[..snapshot.bytes]) {
            return error;
        }
    }
    let metadata = ReadResult {
        next_cursor: snapshot.next,
        dropped: snapshot.dropped,
    }
    .to_bytes();
    match crate::syscall::copy_to_user(result, &metadata) {
        Ok(()) => snapshot.bytes as u64,
        Err(error) => error,
    }
}

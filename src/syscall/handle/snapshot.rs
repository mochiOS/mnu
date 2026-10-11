//! Caller-local metadata observation, not object capture or inheritance policy.
use alloc::vec::Vec;

pub fn table_read(output: u64, capacity: u64) -> u64 {
    use crate::syscall::{EFAULT, EINVAL, ENOSPC};
    if capacity > crate::task::handle_table::PROCESS_MAX_OBJECT_HANDLES as u64
        || (capacity == 0 && output != 0)
    {
        return EINVAL;
    }
    if capacity != 0 && output == 0 {
        return EFAULT;
    }
    let owner = match super::current_process() {
        Ok(owner) => owner,
        Err(error) => return error,
    };
    let Some(records) =
        crate::task::with_process(owner, |process| process.object_handles().describe())
    else {
        return EINVAL;
    };
    if capacity == 0 {
        return records.len() as u64;
    }
    if capacity < records.len() as u64 {
        return ENOSPC;
    }
    // Usercopy may fault or invoke a pager. Never hold the process-table lock
    // while copying; this snapshot carries no references or reservation.
    let mut bytes = Vec::with_capacity(records.len() * 16);
    for record in &records {
        bytes.extend_from_slice(&record.handle.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&record.rights.to_le_bytes());
    }
    if let Err(error) = crate::syscall::copy_to_user(output, &bytes) {
        return error;
    }
    records.len() as u64
}

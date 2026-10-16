//! Caller-local metadata observation, not object capture or inheritance policy.
use alloc::vec::Vec;
use mnu_abi::status::Error;

pub fn table_read(output: u64, capacity: u64) -> u64 {
    if capacity > crate::task::handle_table::PROCESS_MAX_OBJECT_HANDLES as u64
        || (capacity == 0 && output != 0)
    {
        return Error::InvalidArgument.into_raw();
    }
    if capacity != 0 && output == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let owner = match crate::syscall::security::current_process_id() {
        Some(owner) => owner,
        None => return Error::NotReady.into_raw(),
    };
    // Allocate before locking the table. The bounded capacity covers every
    // serialized record; the count-only query never allocates.
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(capacity as usize * 16).is_err() {
        return Error::ResourceUnavailable.into_raw();
    }
    let count = match crate::task::with_process(owner, |process| {
        let records = process.object_handles().describe();
        let count = records.len() as u64;
        if capacity == 0 {
            return Ok(count);
        }
        if capacity < count {
            return Err(Error::LimitExceeded);
        }
        for record in records {
            bytes.extend_from_slice(&record.handle.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&record.rights.to_le_bytes());
        }
        Ok(count)
    }) {
        Some(Ok(count)) => count,
        Some(Err(error)) => return error.into_raw(),
        None => return Error::NotReady.into_raw(),
    };
    // Usercopy may fault or invoke a pager. Never hold the process-table lock
    // while copying; this snapshot carries no references or reservation.
    if capacity != 0 {
        if let Err(error) = crate::syscall::copy_to_user_native(output, &bytes) {
            return error.into_raw();
        }
    }
    count
}

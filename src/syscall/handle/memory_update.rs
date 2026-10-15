//! Private update ownership for a provider endpoint's memory namespace. Only
//! the endpoint RECEIVE capability selects authority; identifiers are opaque.
use alloc::sync::Arc;
use crate::interrupt::spinlock::SpinLock;
use crate::mem::{extent_transaction::ExtentTransaction, vm_object::ObjectKey};
use crate::syscall::{EAGAIN, EINVAL, ENOMEM, ENOSPC, ENOSYS, SUCCESS};
use crate::task::{HandleRights, KernelObject, ObjectHandleEntry};

pub fn create(endpoint: u64, identity: u64, old_length: u64, length: u64) -> u64 {
    if identity == 0 {
        return EINVAL;
    }
    let process_id = match super::current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    // This existing resolver enforces caller-table RECEIVE and exact live
    // thread/slot/generation. Client FileHandle CONTROL is not owner authority.
    let (endpoint_thread_id, endpoint_slot, endpoint_generation) =
        match crate::syscall::ipc::resolve_provider_endpoint(endpoint) {
            Ok(endpoint) => endpoint,
            Err(error) => return error,
        };
    let key = ObjectKey::Provider {
        endpoint_thread_id,
        endpoint_slot,
        endpoint_generation,
        identity,
    };
    let update = match ExtentTransaction::prepare_provider(key, old_length, length) {
        Ok(update) => update,
        Err(error) => return error,
    };
    let update = match Arc::try_new(SpinLock::new(update)) {
        Ok(update) => update,
        Err(_) => return ENOMEM,
    };
    // Failed insertion drops a still-prepared owner into the reserved cleanup
    // queue; it never needs to reacquire VM exclusion from this table lock.
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::MemoryUpdate(update),
                HandleRights::CONTROL,
            ))
            .map(|handle| handle.raw() as u64)
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(EINVAL)
}

pub(super) fn control(
    update: &SpinLock<ExtentTransaction>,
    code: u64,
    input: u64,
    input_length: u64,
    output: u64,
    output_length: u64,
) -> u64 {
    use mnu_abi::memory_update as operation;
    if input != 0 || input_length != 0 || output != 0 || output_length != 0 {
        return EINVAL;
    }
    if !matches!(
        code,
        operation::BEGIN | operation::UNCHANGED | operation::PUBLISH
    ) {
        return ENOSYS;
    }
    // A concurrent caller must not spin with interrupts disabled while an
    // earlier operation is acquiring VM exclusion. No IPC occurs under either.
    let Some(mut update) = update.try_lock() else {
        return EAGAIN;
    };
    match code {
        operation::BEGIN => update.begin_external(),
        operation::UNCHANGED => update.confirm_unchanged(),
        operation::PUBLISH => update.request_external_publication(),
        _ => Err(ENOSYS),
    }
    .err()
    .unwrap_or(SUCCESS)
}

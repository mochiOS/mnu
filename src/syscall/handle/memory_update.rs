//! Private update ownership for a provider endpoint's memory namespace. Only
//! the endpoint RECEIVE capability selects authority; identifiers are opaque.
use crate::interrupt::spinlock::SpinLock;
use crate::mem::{
    extent_transaction::ExtentTransaction,
    vm_object::{ObjectKey, ProviderAdmission},
};
use crate::syscall::{EAGAIN, EINVAL, ENOSYS, SUCCESS};
use crate::task::{HandleRights, KernelObject, ObjectHandleEntry};
use alloc::sync::{Arc, Weak};
use mnu_abi::status::Error;

fn provider_key(endpoint: u64, identity: u64) -> Result<ObjectKey, Error> {
    if identity == 0 {
        return Err(Error::InvalidArgument);
    }
    // The resolver enforces caller-table RECEIVE and exact live
    // thread/slot/generation. Client FileHandle CONTROL is not owner authority.
    let (endpoint_thread_id, endpoint_slot, endpoint_generation) =
        crate::syscall::ipc::resolve_provider_endpoint_native(endpoint)?;
    Ok(ObjectKey::Provider {
        endpoint_thread_id,
        endpoint_slot,
        endpoint_generation,
        identity,
    })
}

pub fn create_admission(endpoint: u64, identity: u64) -> u64 {
    let result = (|| {
        let process_id = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
        let admission = Arc::try_new(ProviderAdmission::new(provider_key(endpoint, identity)?)?)
            .map_err(|_| Error::ResourceUnavailable)?;
        crate::task::with_process_mut(process_id, |process| {
            process
                .object_handles_mut()
                .insert(ObjectHandleEntry::new(
                    KernelObject::MemoryAdmission(admission),
                    HandleRights::WAIT.union(HandleRights::TRANSFER),
                ))
                .map(|handle| handle.raw() as u64)
                .ok_or(Error::ResourceUnavailable)
        })
        .ok_or(Error::NotReady)?
    })();
    result.unwrap_or_else(Error::into_raw)
}

pub fn create(endpoint: u64, identity: u64, old_length: u64, length: u64, admission: u64) -> u64 {
    let process_id = match crate::syscall::security::current_process_id() {
        Some(id) => id,
        None => return Error::NotReady.into_raw(),
    };
    let key = match provider_key(endpoint, identity) {
        Ok(key) => key,
        Err(error) => return error.into_raw(),
    };
    let prepared = if admission == 0 {
        ExtentTransaction::prepare_provider(key, old_length, length)
    } else {
        (|| {
            let KernelObject::MemoryAdmission(admission) =
                super::object_native(admission, HandleRights::WAIT).map_err(Error::into_raw)?
            else {
                return Err(Error::InvalidArgument.into_raw());
            };
            // Consumption drops the intent lock BEFORE VM/process exclusion.
            // The acquired guard itself carries its authenticated backing key.
            let guard = admission
                .acquire(key)
                .map_err(mnu_abi::status::Error::into_raw)?;
            ExtentTransaction::prepare_admitted(guard, old_length, length)
        })()
    };
    let update = match prepared {
        Ok(update) => update,
        Err(error) => return error,
    };
    let update = match Arc::try_new(SpinLock::new(update)) {
        Ok(update) => update,
        Err(_) => return Error::ResourceUnavailable.into_raw(),
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
            .unwrap_or(Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub(super) fn admission_endpoint(
    admission: &ProviderAdmission,
) -> crate::syscall::ipc::IpcEndpoint {
    let (thread_id, slot, generation) = admission.endpoint_parts();
    crate::syscall::ipc::IpcEndpoint {
        thread_id,
        slot,
        generation,
    }
}

pub(super) struct AdmissionWaiter {
    // A sleeping kernel frame must not own the queue position. In particular,
    // closing the final Handle (or tearing down its process) must cancel it
    // even if that frame never resumes to run Rust destructors.
    admission: Weak<ProviderAdmission>,
    waiter: crate::task::ThreadId,
}

impl AdmissionWaiter {
    pub(super) fn register(
        admission: Arc<ProviderAdmission>,
        waiter: crate::task::ThreadId,
    ) -> Result<Self, u64> {
        admission
            .register_waiter(waiter.as_u64(), crate::task::ThreadQueue::MAX_THREADS)
            .map_err(mnu_abi::status::Error::into_raw)?;
        Ok(Self {
            admission: Arc::downgrade(&admission),
            waiter,
        })
    }
}

impl Drop for AdmissionWaiter {
    fn drop(&mut self) {
        if let Some(admission) = self.admission.upgrade() {
            admission.remove_waiter(self.waiter.as_u64());
        }
    }
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

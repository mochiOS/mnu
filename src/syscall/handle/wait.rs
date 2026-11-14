//! Native object waits and owned subscriptions.
use super::*;

#[derive(Clone)]
enum WaitTarget {
    Completion(crate::task::owned_executor::Receipt),
    Process(crate::task::ProcessId),
    IpcEndpoint(crate::ipc::IpcEndpoint),
    Stream(Arc<crate::task::FileHandle>),
    Provider(Arc<ProviderObject>),
    MemoryAdmission(Arc<crate::mem::vm_object::ProviderAdmission>),
}

// Retain ordinary object identity across retries. Admission ownership is the
// queue position itself, so retain only its identity, never its owning Arc.
enum WaitSource {
    Object(KernelObject),
    MemoryAdmission(Weak<crate::mem::vm_object::ProviderAdmission>),
}

impl WaitSource {
    fn capture(object: KernelObject) -> Self {
        match object {
            KernelObject::MemoryAdmission(admission) => {
                Self::MemoryAdmission(Arc::downgrade(&admission))
            }
            object => Self::Object(object),
        }
    }

    fn matches(&self, object: &KernelObject) -> bool {
        match self {
            Self::Object(source) => source.is_same_object(object),
            Self::MemoryAdmission(source) => {
                matches!(object, KernelObject::MemoryAdmission(admission)
                    if Weak::ptr_eq(source, &Arc::downgrade(admission)))
            }
        }
    }
}

pub(super) fn wait_item_signal(
    item: &mut mnu_abi::HandleWaitItem,
    source: &WaitSource,
) -> Result<(WaitTarget, bool), u64> {
    use mnu_abi::status::Error;
    if item.interests == 0 {
        return Err(Error::InvalidArgument.into_raw());
    }
    let object =
        object_native(u64::from(item.handle), HandleRights::WAIT).map_err(Error::into_raw)?;
    // Revalidate authority, but never retarget a pending wait after Handle
    // close/reuse. Admission identity stays weak so close can cancel its ticket.
    if !source.matches(&object) {
        return Err(Error::InvalidArgument.into_raw());
    }
    if item.minimum_write_bytes != 0
        && (!matches!(&object, KernelObject::File(_))
            || item.interests & mnu_abi::HANDLE_SIGNAL_WRITABLE == 0)
    {
        return Err(Error::InvalidArgument.into_raw());
    }
    match object {
        KernelObject::Process(process) => {
            if item.interests & !mnu_abi::HANDLE_SIGNAL_TERMINATED != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            let process_id = process.id();
            let exited = process.is_exited();
            item.observed = if exited {
                mnu_abi::HANDLE_SIGNAL_TERMINATED
            } else {
                0
            };
            Ok((WaitTarget::Process(process_id), exited))
        }
        KernelObject::Completion(receipt) => {
            if item.interests & !mnu_abi::HANDLE_SIGNAL_READABLE != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            let ready = receipt.result().is_some();
            item.observed = if ready {
                mnu_abi::HANDLE_SIGNAL_READABLE
            } else {
                0
            };
            Ok((WaitTarget::Completion(receipt), ready))
        }
        KernelObject::IpcEndpoint {
            thread_id,
            slot,
            generation,
        } => {
            if item.interests & !mnu_abi::HANDLE_SIGNAL_READABLE != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            let endpoint = crate::ipc::IpcEndpoint {
                thread_id,
                slot,
                generation,
            };
            let readable = crate::ipc::endpoint_wait_ready(endpoint)?;
            item.observed = if readable {
                mnu_abi::HANDLE_SIGNAL_READABLE
            } else {
                0
            };
            Ok((WaitTarget::IpcEndpoint(endpoint), readable))
        }
        KernelObject::MemoryAdmission(admission) => {
            let supported = mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            if item.interests & !supported != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            if !crate::ipc::endpoint_is_valid(memory_update::admission_endpoint(&admission)) {
                return Err(Error::NotFound.into_raw());
            }
            item.observed = admission.signals() & item.interests;
            Ok((WaitTarget::MemoryAdmission(admission), item.observed != 0))
        }
        KernelObject::File(file) => {
            let supported = mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            if item.interests & !supported != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            let signals =
                crate::syscall::fs::stream_signals_for_capacity(&file, item.minimum_write_bytes)?;
            item.observed = signals & item.interests;
            Ok((WaitTarget::Stream(file), item.observed != 0))
        }
        KernelObject::Provider(provider) => {
            let supported = mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
                | mnu_abi::HANDLE_SIGNAL_IDLE;
            if item.interests & !supported != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            if !crate::ipc::endpoint_is_valid(provider_endpoint(&provider)) {
                return Err(Error::NotFound.into_raw());
            }
            item.observed = provider.signals() & item.interests;
            Ok((WaitTarget::Provider(provider), item.observed != 0))
        }
        _ => Err(Error::InvalidArgument.into_raw()),
    }
}

pub(super) fn remove_endpoint_waiters(
    waiter: crate::task::ThreadId,
    endpoints: &[crate::ipc::IpcEndpoint],
) {
    for endpoint in endpoints {
        crate::ipc::remove_endpoint_waiter(*endpoint, waiter);
    }
}

pub(super) fn remove_stream_waiters(waiter: crate::task::ThreadId, streams: &[usize]) {
    for stream in streams {
        crate::syscall::fs::remove_stream_waiter(*stream, waiter);
    }
}

pub(super) fn remove_provider_waiters(
    waiter: crate::task::ThreadId,
    providers: &[Arc<ProviderObject>],
) {
    for provider in providers {
        provider.remove_waiter(waiter);
    }
}

/// Own every explicit subscription until the object wait leaves kernel mode.
/// Cleanup is idempotent, including after partial deadline admission.
struct ObjectWaitRegistrations {
    thread: crate::task::ThreadId,
    endpoints: alloc::vec::Vec<crate::ipc::IpcEndpoint>,
    streams: alloc::vec::Vec<usize>,
    providers: alloc::vec::Vec<Arc<ProviderObject>>,
}

impl Drop for ObjectWaitRegistrations {
    fn drop(&mut self) {
        crate::task::remove_process_exit_waiters(self.thread);
        remove_endpoint_waiters(self.thread, &self.endpoints);
        remove_stream_waiters(self.thread, &self.streams);
        remove_provider_waiters(self.thread, &self.providers);
        crate::syscall::time::disarm_thread_deadline(self.thread);
    }
}

/// All allocations, retained objects and subscriptions survive stack discard.
struct ObjectWaitState {
    registrations: ObjectWaitRegistrations,
    endpoint_lifetimes: alloc::vec::Vec<crate::ipc::lifetime::Observation>,
    admission_waiters: alloc::vec::Vec<memory_update::AdmissionWaiter>,
    completion_waiters: alloc::vec::Vec<crate::task::owned_executor::Subscription>,
    sources: alloc::vec::Vec<WaitSource>,
    targets: alloc::vec::Vec<WaitTarget>,
    items: alloc::vec::Vec<mnu_abi::HandleWaitItem>,
    guard_waiter: Option<crate::syscall::address_wait::GuardWaiter>,
}

pub(super) fn copy_wait_items_to_user(
    items_ptr: u64,
    items: &[mnu_abi::HandleWaitItem],
) -> Result<(), u64> {
    let bytes = unsafe {
        core::slice::from_raw_parts(items.as_ptr().cast::<u8>(), core::mem::size_of_val(items))
    };
    crate::syscall::copy_to_user_native(items_ptr, bytes).map_err(mnu_abi::status::Error::into_raw)
}

/// Waits until one of the supplied process-local object handles observes an
/// interested native signal. The return value is the ready item's index.
/// `deadline_nanoseconds` is an absolute monotonic-clock value; zero polls and
/// `u64::MAX` waits indefinitely.
/// Wait-local storage is reserved before subscription; allocation failure is
/// native ResourceUnavailable. All return paths remove subscriptions/deadlines.
/// Array-size validation and usercopy preserve native status::Error categories;
/// the optional guard descriptor is copied once, before checking its predicate.
/// Poll/deadline expiry and pending upcalls return NotReady; exhausted local
/// process/provider subscription slots or deadline storage are ResourceUnavailable.
pub fn wait_many(items_ptr: u64, count: u64, deadline_nanoseconds: u64, guard_ptr: u64) -> u64 {
    use mnu_abi::status::Error;
    let guard = if guard_ptr == 0 {
        None
    } else {
        let mut bytes = [0u8; 16];
        if let Err(error) = crate::syscall::copy_from_user_native(guard_ptr, &mut bytes) {
            return error.into_raw();
        }
        let address = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        let expected = u64::from_ne_bytes(bytes[8..].try_into().unwrap());
        if let Err(error) = crate::syscall::address_wait::read_guard_value(address) {
            return error;
        }
        Some(mnu_abi::HandleWaitGuard { address, expected })
    };
    let count = match usize::try_from(count) {
        Ok(count) if count <= mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS => count,
        _ => return Error::InvalidArgument.into_raw(),
    };
    let byte_len = match count.checked_mul(core::mem::size_of::<mnu_abi::HandleWaitItem>()) {
        Some(length) => length,
        None => return Error::InvalidArgument.into_raw(),
    };
    let mut items = alloc::vec::Vec::new();
    if items.try_reserve_exact(count).is_err() {
        return mnu_abi::status::Error::ResourceUnavailable.into_raw();
    }
    items.resize(count, mnu_abi::HandleWaitItem::default());
    if byte_len != 0 {
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(items.as_mut_ptr().cast::<u8>(), byte_len) };
        if let Err(error) = crate::syscall::copy_from_user_native(items_ptr, bytes) {
            return error.into_raw();
        }
    }
    let current = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return Error::NotReady.into_raw(),
    };
    let mut state = match crate::task::operation::Scope::new(ObjectWaitState {
        registrations: ObjectWaitRegistrations {
            thread: current,
            endpoints: alloc::vec::Vec::new(),
            streams: alloc::vec::Vec::new(),
            providers: alloc::vec::Vec::new(),
        },
        endpoint_lifetimes: alloc::vec::Vec::new(),
        admission_waiters: alloc::vec::Vec::new(),
        completion_waiters: alloc::vec::Vec::new(),
        sources: alloc::vec::Vec::new(),
        targets: alloc::vec::Vec::new(),
        items,
        guard_waiter: None,
    }) {
        Ok(state) => state,
        Err(error) => return error.into_raw(),
    };
    let ObjectWaitState {
        registrations,
        endpoint_lifetimes,
        admission_waiters,
        completion_waiters,
        sources,
        targets,
        items,
        guard_waiter,
    } = &mut *state;
    let registered_endpoints = &mut registrations.endpoints;
    let registered_streams = &mut registrations.streams;
    let registered_providers = &mut registrations.providers;
    // Each item contributes at most one target/subscription of each kind.
    // Reserve before admitting any waiter; no push in the wait loop allocates.
    if registered_endpoints.try_reserve_exact(count).is_err()
        || registered_streams.try_reserve_exact(count).is_err()
        || registered_providers.try_reserve_exact(count).is_err()
        || endpoint_lifetimes.try_reserve_exact(count).is_err()
        || admission_waiters.try_reserve_exact(count).is_err()
        || completion_waiters.try_reserve_exact(count).is_err()
        || sources.try_reserve_exact(count).is_err()
        || targets.try_reserve_exact(count).is_err()
    {
        return mnu_abi::status::Error::ResourceUnavailable.into_raw();
    }
    for item in items.iter() {
        let source = match object_native(u64::from(item.handle), HandleRights::WAIT) {
            Ok(object) => WaitSource::capture(object),
            Err(error) => return error.into_raw(),
        };
        sources.push(source);
    }
    let deadline_tick = if matches!(
        deadline_nanoseconds,
        mnu_abi::HANDLE_WAIT_POLL | mnu_abi::HANDLE_WAIT_INFINITE
    ) {
        deadline_nanoseconds
    } else {
        crate::syscall::time::monotonic_deadline_tick(deadline_nanoseconds)
    };

    loop {
        *guard_waiter = None;
        crate::task::remove_process_exit_waiters(current);
        remove_endpoint_waiters(current, &registered_endpoints);
        remove_stream_waiters(current, &registered_streams);
        remove_provider_waiters(current, &registered_providers);
        registered_endpoints.clear();
        registered_streams.clear();
        registered_providers.clear();
        endpoint_lifetimes.clear();
        admission_waiters.clear();
        completion_waiters.clear();
        crate::syscall::time::disarm_thread_deadline(current);
        targets.clear();
        let mut ready = None;
        for (index, item) in items.iter_mut().enumerate() {
            match wait_item_signal(item, &sources[index]) {
                Ok((_, true)) if ready.is_none() => ready = Some(index),
                Ok((target, _)) => {
                    targets.push(target);
                }
                Err(error) => return error,
            }
        }
        // Guarded waits also subscribe to address wakeups. Registration checks
        // the predicate under the same lock as WakeAddress, so notifications
        // racing with admission cannot strand an otherwise idle object wait.
        *guard_waiter = match guard {
            Some(guard) => {
                match crate::syscall::address_wait::register_guard(
                    current,
                    guard.address,
                    guard.expected,
                ) {
                    Ok(waiter) => Some(waiter),
                    Err(error) if error == mnu_abi::status::Error::NotReady.into_raw() => {
                        return match copy_wait_items_to_user(items_ptr, &items) {
                            Ok(()) => error,
                            Err(error) => error,
                        };
                    }
                    Err(error) => return error,
                }
            }
            None => None,
        };
        if let Some(guard) = guard {
            match crate::syscall::address_wait::read_guard_value(guard.address) {
                Ok(value) if value != guard.expected => {
                    return match copy_wait_items_to_user(items_ptr, &items) {
                        Ok(()) => mnu_abi::status::Error::NotReady.into_raw(),
                        Err(error) => error,
                    };
                }
                Ok(_) => {}
                Err(error) => return error,
            }
        }
        if let Some(index) = ready {
            return match copy_wait_items_to_user(items_ptr, &items) {
                Ok(()) => index as u64,
                Err(error) => error,
            };
        }
        // A queued generic upcall cannot run while this syscall keeps waiting
        // in kernel mode. Registrations and deadlines were cleared above;
        // report no ready object and return so user-mode delivery can proceed.
        // The caller decides whether that notification requires another wait.
        if crate::syscall::upcall::current_has_deliverable_upcall() {
            return match copy_wait_items_to_user(items_ptr, &items) {
                Ok(()) => Error::NotReady.into_raw(),
                Err(error) => error,
            };
        }
        if deadline_nanoseconds == mnu_abi::HANDLE_WAIT_POLL
            || (deadline_nanoseconds != mnu_abi::HANDLE_WAIT_INFINITE
                && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds)
        {
            if items.is_empty() {
                return Error::NotReady.into_raw();
            }
            return match copy_wait_items_to_user(items_ptr, &items) {
                Ok(()) => Error::NotReady.into_raw(),
                Err(error) => error,
            };
        }
        for target in targets.drain(..) {
            match target {
                WaitTarget::Completion(receipt) => match receipt.subscribe(current.as_u64()) {
                    Ok(Some(subscription)) => completion_waiters.push(subscription),
                    Ok(None) => {}
                    Err(error) => return error.into_raw(),
                },
                WaitTarget::MemoryAdmission(admission) => {
                    let registered = (|| {
                        let endpoint = memory_update::admission_endpoint(&admission);
                        let observation = crate::ipc::lifetime::observe(endpoint, current)?;
                        let waiter = memory_update::AdmissionWaiter::register(admission, current)?;
                        admission_waiters.push(waiter);
                        endpoint_lifetimes.push(observation);
                        Ok::<(), u64>(())
                    })();
                    if let Err(error) = registered {
                        return error;
                    }
                }
                WaitTarget::Process(process_id) => {
                    if !crate::task::register_process_exit_waiter(current, process_id) {
                        return Error::ResourceUnavailable.into_raw();
                    }
                }
                WaitTarget::IpcEndpoint(endpoint) => {
                    if let Err(error) = crate::ipc::register_endpoint_waiter(endpoint, current) {
                        return error;
                    }
                    registered_endpoints.push(endpoint);
                }
                WaitTarget::Stream(stream) => {
                    match crate::syscall::fs::register_stream_waiter(&stream, current) {
                        Ok(stream_id) => registered_streams.push(stream_id),
                        Err(error) => {
                            return error;
                        }
                    }
                }
                WaitTarget::Provider(provider) => {
                    match crate::ipc::lifetime::observe(provider_endpoint(&provider), current) {
                        Ok(observation) => endpoint_lifetimes.push(observation),
                        Err(error) => {
                            return error;
                        }
                    }
                    if !provider.register_waiter(current) {
                        return Error::ResourceUnavailable.into_raw();
                    }
                    registered_providers.push(provider);
                }
            }
        }
        if deadline_nanoseconds != mnu_abi::HANDLE_WAIT_INFINITE
            && !crate::syscall::time::arm_thread_deadline(current, deadline_tick)
        {
            return Error::ResourceUnavailable.into_raw();
        }

        // Recheck after waiter registration so exits racing with registration
        // cannot be missed. A pending wakeup prevents sleeping in that case.
        let mut became_ready = false;
        for (index, item) in items.iter_mut().enumerate() {
            match wait_item_signal(item, &sources[index]) {
                Ok((_, is_ready)) => became_ready |= is_ready,
                Err(error) => {
                    return error;
                }
            }
        }
        if became_ready {
            continue;
        }
        let _ = crate::task::sleep_thread_unless_woken(current);
        crate::task::yield_now();
    }
}

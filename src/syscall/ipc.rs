use crate::interrupt::spinlock::{SpinLock, SpinLockGuard};
use alloc::alloc::{alloc, Layout};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub(crate) mod lifetime;

use crate::task::{HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry};

use super::{EACCES, EAGAIN, EBADF, EFAULT, EINVAL, EIO, EMSGSIZE, ENOSPC};

const MAX_THREADS: usize = crate::task::ThreadQueue::MAX_THREADS;
const MAILBOX_CAP: usize = 64;
const MESSAGE_CACHE_CAP: usize = MAILBOX_CAP;
const MAX_MSG_SIZE: usize = crate::config::IPC_MESSAGE_CAPACITY;
const MAX_OBJECT_HANDLES: usize = mnu_abi::IPC_MAX_OBJECT_HANDLES;

/// endpoint ベース IPC への移行用ハンドル
///
/// 既存の thread-ID ベースの mailbox を直接露出せず、世代番号付きの endpoint を
/// 受け渡すための薄いラッパとして使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcEndpoint {
    pub thread_id: u64,
    pub slot: u16,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointRights(u8);

impl EndpointRights {
    pub const SEND: Self = Self(0x1);
    pub const RECV: Self = Self(0x2);
    pub const CREATE: Self = Self(0x4);
    pub const MANAGE: Self = Self(0x8);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug)]
struct EndpointRecord {
    thread_id: u64,
    slot: u16,
    generation: u64,
    rights: EndpointRights,
}

// Endpoint handles and legacy thread IDs are both accepted by IPC syscalls.
// Keep handles in a disjoint opaque range so a thread ID can never resolve to
// an unrelated endpoint merely because both counters reached the same value.
// The sender handle is carried in the upper 32 bits of a successful syscall
// result, so it must also stay below bit 31 to keep that result non-negative.
const ENDPOINT_HANDLE_BASE: u64 = 0x4000_0000;
const ENDPOINT_HANDLE_LIMIT: u64 = 0x7fff_ffff;
static NEXT_ENDPOINT_HANDLE: AtomicU64 = AtomicU64::new(ENDPOINT_HANDLE_BASE);
static NEXT_CALL_ID: AtomicU64 = AtomicU64::new(1);
static ENDPOINTS: Mutex<Option<BTreeMap<u64, EndpointRecord>>> = Mutex::new(None);
static THREAD_DEFAULT_ENDPOINTS: Mutex<Option<BTreeMap<u64, u64>>> = Mutex::new(None);

pub fn endpoint_for_thread(thread_id: u64) -> Option<IpcEndpoint> {
    let (slot, generation) = crate::task::thread_slot_index_and_generation_by_u64(thread_id)?;
    Some(IpcEndpoint {
        thread_id,
        slot: slot as u16,
        generation,
    })
}

/// 指定スレッドに紐づく既定 endpoint handle を返す。
///
/// まだ handle がなければ新規に作成する。
pub fn ensure_endpoint_handle_for_thread(thread_id: u64) -> Option<u64> {
    ensure_endpoint_for_thread(thread_id)
}

pub fn endpoint_is_valid(endpoint: IpcEndpoint) -> bool {
    match crate::task::thread::live_thread_slot_index_and_generation_by_u64(endpoint.thread_id) {
        Some((slot, generation)) => {
            slot as u16 == endpoint.slot && generation == endpoint.generation
        }
        None => false,
    }
}

pub fn endpoint_rights_for_process(process_id: u64) -> EndpointRights {
    let process_id = crate::task::ProcessId::from_u64(process_id);
    let mut rights = EndpointRights::empty();
    if crate::task::process::process_has_capability(
        process_id,
        crate::capability::Capability::IpcClient,
    ) {
        rights = rights.union(EndpointRights::SEND);
    }
    if crate::task::process::process_has_capability(
        process_id,
        crate::capability::Capability::IpcServer,
    ) {
        rights = rights.union(EndpointRights::RECV);
    }
    rights
}

fn with_endpoints_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, EndpointRecord>) -> R) -> R {
    let mut guard = ENDPOINTS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn with_default_endpoints_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, u64>) -> R) -> R {
    let mut guard = THREAD_DEFAULT_ENDPOINTS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn endpoint_record_is_valid(record: &EndpointRecord) -> bool {
    endpoint_is_valid(IpcEndpoint {
        thread_id: record.thread_id,
        slot: record.slot,
        generation: record.generation,
    })
}

fn endpoint_record_from_handle(handle: u64) -> Option<EndpointRecord> {
    with_endpoints_mut(|endpoints| endpoints.get(&handle).copied())
        .filter(|record| endpoint_record_is_valid(record))
}

pub fn endpoint_alive(handle: u64) -> u64 {
    if handle != 0 && endpoint_record_from_handle(handle).is_some() {
        super::SUCCESS
    } else {
        super::EINVAL
    }
}

pub fn endpoint_owner_process(handle: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return EACCES;
    }
    let Some(record) = endpoint_record_from_handle(handle) else {
        return EINVAL;
    };
    crate::task::thread_to_process_id(record.thread_id)
        .map(|process_id| process_id.as_u64())
        .unwrap_or(EINVAL)
}

/// Resolve only a generation-checked IPC endpoint. This grants no object
/// authority and exposes no credentials, parent relationship or service policy.
pub fn endpoint_execution_identity(handle: u64) -> Result<mnu_abi::ExecutionIdentity, u64> {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return Err(EACCES);
    }
    let record = endpoint_record_from_handle(handle).ok_or(EINVAL)?;
    let process = crate::task::thread_to_process_id(record.thread_id).ok_or(super::ESRCH)?;
    Ok(mnu_abi::ExecutionIdentity {
        process_id: process.as_u64(),
        thread_id: record.thread_id,
    })
}

pub fn endpoint_is_owned_by(handle: u64, process_id: crate::task::ProcessId) -> bool {
    let Some(record) = endpoint_record_from_handle(handle) else {
        return false;
    };
    crate::task::thread_to_process_id(record.thread_id) == Some(process_id)
        && record.rights.contains(EndpointRights::RECV)
}

fn endpoint_rights_for_thread(thread_id: u64) -> EndpointRights {
    let Some(pid) = crate::task::thread_to_process_id(thread_id) else {
        return EndpointRights::empty();
    };
    endpoint_rights_for_process(pid.as_u64())
}

fn endpoint_handle_for_thread(thread_id: u64) -> Option<u64> {
    let handle = with_default_endpoints_mut(|defaults| defaults.get(&thread_id).copied());
    let Some(handle) = handle else {
        return None;
    };
    if endpoint_record_from_handle(handle).is_some() {
        Some(handle)
    } else {
        with_default_endpoints_mut(|defaults| {
            if defaults.get(&thread_id).copied() == Some(handle) {
                defaults.remove(&thread_id);
            }
        });
        None
    }
}

fn ensure_endpoint_for_thread(thread_id: u64) -> Option<u64> {
    if let Some(handle) = endpoint_handle_for_thread(thread_id) {
        return Some(handle);
    }
    let (slot, generation) = crate::task::thread_slot_index_and_generation_by_u64(thread_id)?;
    let rights = endpoint_rights_for_thread(thread_id);
    let handle = NEXT_ENDPOINT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle > ENDPOINT_HANDLE_LIMIT {
        return None;
    }
    let record = EndpointRecord {
        thread_id,
        slot: slot as u16,
        generation,
        rights,
    };
    with_endpoints_mut(|endpoints| {
        endpoints.insert(handle, record);
    });
    with_default_endpoints_mut(|defaults| {
        defaults.insert(thread_id, handle);
    });
    Some(handle)
}

pub fn resolve_endpoint_handle(dest: u64) -> Option<u64> {
    endpoint_record_from_handle(dest).map(|record| record.thread_id)
}

pub fn resolve_sender_thread_id(sender: u64) -> Option<u64> {
    resolve_endpoint_handle(sender)
        .or_else(|| crate::task::thread_slot_index_and_generation_by_u64(sender).map(|_| sender))
}

pub fn create(flags: u64, _reserved: u64) -> u64 {
    if flags != 0 {
        return EINVAL;
    }
    let thread_id = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    ensure_endpoint_for_thread(thread_id).unwrap_or(EINVAL)
}

/// Creates a process-local IPC endpoint handle.
///
/// Unlike the transitional global endpoint number returned by `create`, this
/// value is meaningful only in the caller's object-handle table.
pub fn create_handle(flags: u64, _reserved: u64) -> u64 {
    if flags != 0 {
        return EINVAL;
    }
    let thread_id = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let process_id = match crate::task::thread_to_process_id(thread_id) {
        Some(process_id) => process_id,
        None => return EINVAL,
    };
    let endpoint = match endpoint_for_thread(thread_id) {
        Some(endpoint) => endpoint,
        None => return EINVAL,
    };
    let endpoint_rights = endpoint_rights_for_process(process_id.as_u64());
    let mut rights = HandleRights::DUPLICATE.union(HandleRights::TRANSFER);
    if endpoint_rights.contains(EndpointRights::SEND) {
        rights = rights.union(HandleRights::SEND);
    }
    if endpoint_rights.contains(EndpointRights::RECV) {
        rights = rights
            .union(HandleRights::RECEIVE)
            .union(HandleRights::WAIT);
    }
    let entry = ObjectHandleEntry::new(
        KernelObject::IpcEndpoint {
            thread_id: endpoint.thread_id,
            slot: endpoint.slot,
            generation: endpoint.generation,
        },
        rights,
    );
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(entry)
            .map(|handle| handle.raw() as u64)
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(EINVAL)
}

pub(crate) fn endpoint_wait_ready(endpoint: IpcEndpoint) -> Result<bool, u64> {
    if !endpoint_is_valid(endpoint) {
        return Err(EINVAL);
    }
    let mailboxes = lock_mailboxes();
    let mailbox = mailboxes.get(endpoint.slot as usize).ok_or(EINVAL)?;
    Ok(mailbox.count > 0)
}

pub(crate) fn register_endpoint_waiter(
    endpoint: IpcEndpoint,
    waiter: crate::task::ThreadId,
) -> Result<(), u64> {
    if !endpoint_is_valid(endpoint) || endpoint.thread_id != waiter.as_u64() {
        return Err(EACCES);
    }
    let mut mailboxes = lock_mailboxes();
    let mailbox = mailboxes.get_mut(endpoint.slot as usize).ok_or(EINVAL)?;
    if mailbox.waiter != 0 && mailbox.waiter != waiter.as_u64() {
        return Err(EAGAIN);
    }
    mailbox.waiter = waiter.as_u64();
    Ok(())
}

pub(crate) fn remove_endpoint_waiter(endpoint: IpcEndpoint, waiter: crate::task::ThreadId) {
    if !endpoint_is_valid(endpoint) {
        return;
    }
    let mut mailboxes = lock_mailboxes();
    if let Some(mailbox) = mailboxes.get_mut(endpoint.slot as usize) {
        if mailbox.waiter == waiter.as_u64() {
            mailbox.waiter = 0;
        }
    }
}

fn process_local_endpoint(raw: u64, required: HandleRights) -> Result<IpcEndpoint, u64> {
    let raw = u32::try_from(raw).map_err(|_| EBADF)?;
    let handle = ObjectHandle::from_raw(raw).ok_or(EBADF)?;
    let process_id = crate::syscall::security::current_process_id().ok_or(EINVAL)?;
    let entry = crate::task::with_process(process_id, |process| {
        process.object_handles().get(handle)
    })
    .flatten()
    .ok_or(EBADF)?;
    if !entry.rights().contains(required) {
        return Err(EACCES);
    }
    let KernelObject::IpcEndpoint {
        thread_id,
        slot,
        generation,
    } = entry.object()
    else {
        return Err(EINVAL);
    };
    let endpoint = IpcEndpoint {
        thread_id: *thread_id,
        slot: *slot,
        generation: *generation,
    };
    endpoint_is_valid(endpoint).then_some(endpoint).ok_or(EINVAL)
}

pub(crate) fn resolve_provider_endpoint(raw: u64) -> Result<(u64, u16, u64), u64> {
    let endpoint = process_local_endpoint(raw, HandleRights::RECEIVE)?;
    Ok((
        endpoint.thread_id,
        endpoint.slot,
        endpoint.generation,
    ))
}

fn resolve_call_destination(raw: u64) -> Result<(u64, u64, u32), u64> {
    if raw <= crate::task::PROCESS_MAX_OBJECT_HANDLES as u64 {
        let endpoint = process_local_endpoint(raw, HandleRights::SEND)?;
        let sender_identity = ensure_endpoint_for_thread(endpoint.thread_id).ok_or(EINVAL)?;
        return Ok((
            endpoint.thread_id,
            sender_identity,
            mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
        ));
    }
    let record = endpoint_record_from_handle(raw).ok_or(EINVAL)?;
    if !record.rights.contains(EndpointRights::RECV) {
        return Err(EACCES);
    }
    Ok((record.thread_id, raw, 0))
}

fn resolve_receive_thread(raw: u64, current_thread_id: u64) -> Result<u64, u64> {
    let thread_id = if raw <= crate::task::PROCESS_MAX_OBJECT_HANDLES as u64 {
        process_local_endpoint(raw, HandleRights::RECEIVE)?.thread_id
    } else {
        let record = endpoint_record_from_handle(raw).ok_or(EINVAL)?;
        if !record.rights.contains(EndpointRights::RECV) {
            return Err(EACCES);
        }
        record.thread_id
    };
    if thread_id != current_thread_id {
        return Err(EACCES);
    }
    Ok(thread_id)
}

pub fn call(
    dest_endpoint_handle: u64,
    req_ptr: u64,
    req_len: u64,
    reply_ptr: u64,
    reply_len: u64,
) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let (dest_thread_id, expected_sender, delivery_flags) =
        match resolve_call_destination(dest_endpoint_handle) {
            Ok(destination) => destination,
            Err(error) => return error,
        };
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let sender = match ensure_endpoint_for_thread(caller) {
        Some(handle) => handle,
        None => return EINVAL,
    };
    let destination = match endpoint_for_thread(dest_thread_id) {
        Some(endpoint) => endpoint,
        None => return super::ESRCH,
    };
    let _lifetime = match lifetime::observe(destination, crate::task::ThreadId::from_u64(caller)) {
        Ok(observation) => observation,
        Err(error) => return error,
    };
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    #[cfg(feature = "performance-instrumentation")]
    let round_trip_start = crate::performance::timestamp();
    let sent = loop {
        if !endpoint_is_valid(destination) {
            return super::ESRCH;
        }
        let status = send_call_to_thread_id(
            dest_thread_id, sender, call_id, req_ptr, req_len, delivery_flags,
        );
        if status != EAGAIN {
            break status;
        }
        crate::task::yield_now();
    };
    if sent != 0 {
        return sent;
    }
    let result = recv_blocking_reply_for_thread(
        caller,
        caller,
        expected_sender,
        call_id,
        reply_ptr,
        reply_len,
        None,
        destination,
    );
    #[cfg(feature = "performance-instrumentation")]
    if (result as i64) >= 0 {
        crate::performance::record_latency(
            crate::performance::LatencyMetric::IpcSmallRoundTrip,
            round_trip_start,
        );
    }
    result
}

/// Performs a synchronous IPC call with rights-restricted generic object
/// handles in both directions.
///
/// `handles_ptr` is an in/out `IpcObjectHandles`: its initial contents are
/// attached to the request and it is replaced with the handles attached to the
/// reply. Handle numbers remain process-local on both sides.
pub fn call_object_handles(
    dest_endpoint_handle: u64,
    req_ptr: u64,
    req_len: u64,
    reply_ptr: u64,
    reply_len: u64,
    handles_ptr: u64,
) -> u64 {
    if handles_ptr == 0 {
        return EFAULT;
    }
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let (dest_thread_id, expected_sender, delivery_flags) =
        match resolve_call_destination(dest_endpoint_handle) {
            Ok(destination) => destination,
            Err(error) => return error,
        };
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let sender = match ensure_endpoint_for_thread(caller) {
        Some(handle) => handle,
        None => return EINVAL,
    };
    let destination = match endpoint_for_thread(dest_thread_id) {
        Some(endpoint) => endpoint,
        None => return super::ESRCH,
    };
    let _lifetime = match lifetime::observe(destination, crate::task::ThreadId::from_u64(caller)) {
        Ok(observation) => observation,
        Err(error) => return error,
    };
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let sent = loop {
        if !endpoint_is_valid(destination) {
            return super::ESRCH;
        }
        let mut attachments = match decode_outgoing_object_handles(handles_ptr) {
            Ok(handles) => handles,
            Err(error) => return error,
        };
        attachments.delivery_flags = delivery_flags;
        let status = send_to_thread_id_with_attachments(
            dest_thread_id,
            sender,
            call_id,
            req_ptr,
            req_len,
            false,
            true,
            attachments,
        );
        if status != EAGAIN {
            break status;
        }
        crate::task::yield_now();
    };
    if sent != 0 {
        return sent;
    }
    recv_blocking_reply_for_thread(
        caller,
        caller,
        expected_sender,
        call_id,
        reply_ptr,
        reply_len,
        Some(handles_ptr),
        destination,
    )
}

pub fn reply(dest_thread_id: u64, buf_ptr: u64, len: u64) -> u64 {
    reply_with_attachments(
        dest_thread_id,
        buf_ptr,
        len,
        ObjectHandleAttachments::empty(),
    )
}

/// Replies to a synchronous call and transfers rights-restricted generic
/// object handles to the caller.
pub fn reply_object_handles(
    dest_thread_id: u64,
    buf_ptr: u64,
    len: u64,
    handles_ptr: u64,
) -> u64 {
    let attachments = match decode_outgoing_object_handles(handles_ptr) {
        Ok(handles) => handles,
        Err(error) => return error,
    };
    reply_with_attachments(dest_thread_id, buf_ptr, len, attachments)
}

fn reply_with_attachments(
    dest_thread_id: u64,
    buf_ptr: u64,
    len: u64,
    object_handles: ObjectHandleAttachments,
) -> u64 {
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let caller_handle = match ensure_endpoint_for_thread(current) {
        Some(handle) => handle,
        None => return EINVAL,
    };
    let target = {
        let boxes = lock_mailboxes();
        let (idx, generation) = match crate::task::thread_slot_index_and_generation_by_u64(current) {
            Some(v) => v,
            None => return EINVAL,
        };
        if idx >= MAX_THREADS {
            return EINVAL;
        }
        match boxes[idx].reply_target(dest_thread_id, (current, generation)) {
            Some(target) => target,
            None => return EACCES,
        }
    };
    if target.endpoint == 0 {
        return EINVAL;
    }
    let target_thread = match resolve_endpoint_handle(target.endpoint) {
        Some(thread_id) => thread_id,
        None => return EINVAL,
    };
    let status = send_to_thread_id_with_attachments(
        target_thread,
        caller_handle,
        target.call_id,
        buf_ptr,
        len,
        true,
        false,
        object_handles,
    );
    if status == 0 {
        let mut boxes = lock_mailboxes();
        if let Some((idx, _)) = crate::task::thread_slot_index_and_generation_by_u64(current) {
            if idx < MAX_THREADS {
                boxes[idx].remove_reply_target(target);
            }
        }
    }
    status
}

fn recv_blocking_reply_for_thread(
    receiver_thread_id: u64,
    caller_thread_id: u64,
    expected_sender: u64,
    expected_call_id: u64,
    buf_ptr: u64,
    max_len: u64,
    object_handles_output: Option<u64>,
    destination: IpcEndpoint,
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    loop {
        let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
        let recv = {
            let mut boxes = lock_mailboxes();
            match boxes[idx].pop_reply_to_user(
                expected_sender,
                expected_call_id,
                receiver_thread_id,
                idx as u16,
                receiver_generation,
                buf_ptr,
                max_copy,
                object_handles_output.is_some(),
            ) {
                Ok(Some(v)) => Some(v),
                Ok(None) => {
                    boxes[idx].waiter = caller_thread_id;
                    None
                }
                Err(error) => return error,
            }
        };

        match recv {
            Some(receive) => {
                let (from, copy_len, _) = match finish_user_receive(
                    receiver_thread_id,
                    receive,
                    object_handles_output,
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                return (from << 32) | (copy_len as u64);
            }
            None => {
                {
                    let mut boxes = lock_mailboxes();
                    let second_try = boxes[idx].pop_reply_to_user(
                        expected_sender,
                        expected_call_id,
                        receiver_thread_id,
                        idx as u16,
                        receiver_generation,
                        buf_ptr,
                        max_copy,
                        object_handles_output.is_some(),
                    );
                    if let Ok(Some(receive)) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        drop(boxes);
                        let (from, copy_len, _) = match finish_user_receive(
                            receiver_thread_id,
                            receive,
                            object_handles_output,
                        ) {
                            Ok(result) => result,
                            Err(error) => return error,
                        };
                        return (from << 32) | (copy_len as u64);
                    }
                    if let Err(error) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        return error;
                    }
                }
                if !endpoint_is_valid(destination) {
                    let mut boxes = lock_mailboxes();
                    if boxes[idx].waiter == caller_thread_id {
                        boxes[idx].waiter = 0;
                    }
                    return super::ESRCH;
                }
                if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(
                    caller_thread_id,
                )) {
                    crate::task::yield_now();
                } else {
                    // The caller's mailbox also carries ordinary events. A wakeup
                    // without a reply must not abort an already-delivered IPC call.
                    let mut boxes = lock_mailboxes();
                    if boxes[idx].waiter == caller_thread_id {
                        boxes[idx].waiter = 0;
                    }
                }
            }
        }
    }
}

pub fn wait(buf_ptr: u64, max_len: u64, blocking: u64) -> u64 {
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(current);
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len, None);
    }
    let target = match resolve_receive_thread(blocking, current) {
        Ok(thread_id) => thread_id,
        Err(error) => return error,
    };
    recv_blocking_for_thread(target, current, buf_ptr, max_len, None)
}

pub fn send_to_endpoint(endpoint: IpcEndpoint, buf_ptr: u64, len: u64) -> u64 {
    if !endpoint_is_valid(endpoint) {
        return EINVAL;
    }
    send(endpoint.thread_id, buf_ptr, len)
}

#[inline]
fn ipc_mailbox_cap() -> usize {
    // At least one ordinary message and one synchronous reply must fit.
    crate::config::kernel()
        .ipc
        .mailbox_cap
        .clamp(2, MAILBOX_CAP)
}

#[inline]
fn ipc_max_msg_size() -> usize {
    crate::config::kernel().ipc.max_msg_size.min(MAX_MSG_SIZE)
}

#[inline]
fn record_ipc_copy(bytes: usize) {
    crate::performance::increment(
        crate::performance::CounterMetric::IpcBytesCopied,
        bytes as u64,
    );
}

fn decode_outgoing_object_handles(pointer: u64) -> Result<ObjectHandleAttachments, u64> {
    if pointer == 0 {
        return Err(EFAULT);
    }
    let mut bytes = [0u8; core::mem::size_of::<mnu_abi::IpcObjectHandles>()];
    crate::syscall::copy_from_user(pointer, &mut bytes)?;
    let count = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| EINVAL)?) as usize;
    let delivery_flags = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| EINVAL)?);
    if count > MAX_OBJECT_HANDLES || delivery_flags != 0 {
        return Err(EINVAL);
    }
    let process_id = crate::syscall::security::current_process_id().ok_or(EINVAL)?;
    let mut attachments = ObjectHandleAttachments::empty();
    for index in 0..count {
        let offset = 8 + index * 16;
        let raw = u32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| EINVAL)?);
        let item_reserved =
            u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().map_err(|_| EINVAL)?);
        let requested_bits =
            u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().map_err(|_| EINVAL)?);
        if item_reserved != 0 {
            return Err(EINVAL);
        }
        let handle = ObjectHandle::from_raw(raw).ok_or(EBADF)?;
        let requested = HandleRights::from_bits(requested_bits).ok_or(EINVAL)?;
        let exported = export_object_handle(process_id, handle, requested)?;
        attachments.handles[index] = Some(exported);
        attachments.count += 1;
    }
    Ok(attachments)
}

fn export_object_handle(
    process_id: crate::task::ProcessId,
    handle: ObjectHandle,
    requested: HandleRights,
) -> Result<ObjectHandleEntry, u64> {
    crate::task::with_process(process_id, |process| {
        let source = process.object_handles().get(handle).ok_or(EBADF)?;
        if !source.rights().contains(HandleRights::TRANSFER)
            || !source.rights().contains(requested)
        {
            return Err(EACCES);
        }
        process
            .object_handles()
            .export_restricted(handle, requested)
            .ok_or(EACCES)
    })
    .ok_or(EBADF)?
}

fn install_received_object_handles(
    receiver_thread_id: u64,
    mut attachments: ObjectHandleAttachments,
    output_pointer: u64,
) -> Result<(), u64> {
    let process_id = crate::task::thread_to_process_id(receiver_thread_id).ok_or(EINVAL)?;
    let mut installed = [None; MAX_OBJECT_HANDLES];
    let mut rights = [0u64; MAX_OBJECT_HANDLES];
    let count = attachments.count;
    let result = crate::task::with_process_mut(process_id, |process| {
        for index in 0..count {
            let entry = attachments.handles[index].take().ok_or(EINVAL)?;
            rights[index] = entry.rights().bits();
            let Some(handle) = process.object_handles_mut().insert(entry) else {
                for installed_handle in installed[..index].iter().flatten().copied() {
                    let _ = process.object_handles_mut().close(installed_handle);
                }
                return Err(ENOSPC);
            };
            installed[index] = Some(handle);
        }
        Ok(())
    })
    .ok_or(EINVAL)?;
    result?;

    let mut output = [0u8; core::mem::size_of::<mnu_abi::IpcObjectHandles>()];
    output[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    output[4..8].copy_from_slice(&attachments.delivery_flags.to_le_bytes());
    for index in 0..count {
        let offset = 8 + index * 16;
        let raw = installed[index].ok_or(EINVAL)?.raw();
        output[offset..offset + 4].copy_from_slice(&raw.to_le_bytes());
        output[offset + 8..offset + 16].copy_from_slice(&rights[index].to_le_bytes());
    }
    if let Err(error) = crate::syscall::copy_to_user(output_pointer, &output) {
        let _ = crate::task::with_process_mut(process_id, |process| {
            for handle in installed[..count].iter().flatten().copied() {
                let _ = process.object_handles_mut().close(handle);
            }
        });
        return Err(error);
    }
    Ok(())
}

#[derive(Debug)]
struct ObjectHandleAttachments {
    count: usize,
    delivery_flags: u32,
    handles: [Option<ObjectHandleEntry>; MAX_OBJECT_HANDLES],
}

impl ObjectHandleAttachments {
    const fn empty() -> Self {
        Self {
            count: 0,
            delivery_flags: 0,
            handles: [const { None }; MAX_OBJECT_HANDLES],
        }
    }

    const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Debug)]
pub struct Message {
    from: u64,
    to: u64,
    to_slot: u16,
    to_generation: u64,
    is_reply: bool,
    expects_reply: bool,
    call_id: u64,
    len: usize,
    data: [u8; MAX_MSG_SIZE],
    object_handles: ObjectHandleAttachments,
}

impl Message {
    const fn empty() -> Self {
        Self {
            from: 0,
            to: 0,
            to_slot: 0,
            to_generation: 0,
            is_reply: false,
            expects_reply: false,
            call_id: 0,
            len: 0,
            data: [0; MAX_MSG_SIZE],
            object_handles: ObjectHandleAttachments::empty(),
        }
    }
}

struct UserReceive {
    from: u64,
    copy_len: usize,
    expects_reply: bool,
    call_id: u64,
    object_handles: ObjectHandleAttachments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplyTarget {
    endpoint: u64,
    call_id: u64,
}

#[derive(Debug)]
struct Mailbox {
    head: usize,
    tail: usize,
    count: usize,
    queue: [u8; MAILBOX_CAP],
    slots: [Option<Box<Message>>; MAILBOX_CAP],
    free: [u8; MAILBOX_CAP],
    free_count: usize,
    /// メッセージ待ちでスリープ中のスレッドID (0=なし)
    waiter: u64,
    /// Endpoints whose synchronous calls this thread has received and may
    /// answer later.
    reply_targets: Vec<ReplyTarget>,
    reply_owner: Option<(u64, u64)>,
}

impl Mailbox {
    const fn new() -> Self {
        let mut free = [0u8; MAILBOX_CAP];
        let mut i = 0;
        while i < MAILBOX_CAP {
            free[i] = i as u8;
            i += 1;
        }
        Self {
            head: 0,
            tail: 0,
            count: 0,
            queue: [0; MAILBOX_CAP],
            slots: [const { None }; MAILBOX_CAP],
            free,
            free_count: MAILBOX_CAP,
            waiter: 0,
            reply_targets: Vec::new(),
            reply_owner: None,
        }
    }

    fn add_reply_target(&mut self, endpoint: u64, call_id: u64, owner: (u64, u64)) {
        // Mailboxes are indexed by reusable thread slots. Reply authority may
        // never survive into a different thread or a new slot generation.
        if self.reply_owner != Some(owner) {
            self.reply_targets.clear();
            self.reply_owner = Some(owner);
        }
        let target = ReplyTarget { endpoint, call_id };
        if endpoint != 0 && call_id != 0 && !self.reply_targets.contains(&target) {
            self.reply_targets.push(target);
        }
    }

    fn reply_target(&self, endpoint: u64, owner: (u64, u64)) -> Option<ReplyTarget> {
        if self.reply_owner != Some(owner) {
            return None;
        }
        self.reply_targets
            .iter()
            .copied()
            .find(|target| target.endpoint == endpoint)
    }

    fn remove_reply_target(&mut self, target: ReplyTarget) {
        if let Some(index) = self.reply_targets.iter().position(|value| *value == target) {
            self.reply_targets.swap_remove(index);
        }
    }

    fn reserve_slot(&mut self, is_reply: bool) -> Option<usize> {
        // A caller waiting for a reply cannot drain ordinary notifications.
        // Keep one queue slot available for its outstanding synchronous call.
        let limit = ipc_mailbox_cap().saturating_sub(usize::from(!is_reply));
        if self.free_count == 0 || self.count >= limit {
            return None;
        }
        self.free_count -= 1;
        let idx = self.free[self.free_count] as usize;
        if idx >= MAILBOX_CAP || self.slots[idx].is_some() {
            self.quarantine("ipc mailbox free list points to an occupied slot");
            return None;
        }
        Some(idx)
    }

    fn alloc_slot(&mut self) -> Option<usize> {
        let message = allocate_message()?;
        let Some(idx) = self.reserve_slot(false) else {
            release_message(message);
            return None;
        };
        self.slots[idx] = Some(message);
        Some(idx)
    }

    fn enqueue_message(&mut self, message: Box<Message>) -> Result<(), ()> {
        let Some(slot_idx) = self.reserve_slot(message.is_reply) else {
            release_message(message);
            return Err(());
        };
        self.slots[slot_idx] = Some(message);
        if self.enqueue_slot(slot_idx).is_err() {
            let _ = self.free_slot(slot_idx);
            return Err(());
        }
        Ok(())
    }

    fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
        for message in self.slots.iter_mut().filter_map(Option::take) {
            release_message(message);
        }
        *self = Self::new();
    }

    fn free_slot(&mut self, idx: usize) -> bool {
        match self.take_slot(idx) {
            Some(message) => {
                release_message(message);
                true
            }
            None => false,
        }
    }

    fn take_slot(&mut self, idx: usize) -> Option<Box<Message>> {
        if idx >= MAILBOX_CAP {
            self.quarantine("ipc mailbox free list corrupted: slot index out of range");
            return None;
        }
        if self.free_count >= MAILBOX_CAP {
            self.quarantine("ipc mailbox free list corrupted: free_count overflow");
            return None;
        }
        for i in 0..self.free_count {
            if self.free[i] as usize == idx {
                self.quarantine("ipc mailbox free list corrupted: double free");
                return None;
            }
        }

        let Some(message) = self.slots[idx].take() else {
            self.quarantine("ipc mailbox slot missing during free");
            return None;
        };
        self.free[self.free_count] = idx as u8;
        self.free_count += 1;
        Some(message)
    }

    fn enqueue_slot(&mut self, slot_idx: usize) -> Result<(), ()> {
        if self.count >= MAILBOX_CAP {
            return Err(());
        }
        self.queue[self.tail] = slot_idx as u8;
        self.tail = (self.tail + 1) % MAILBOX_CAP;
        self.count += 1;
        Ok(())
    }

    fn dequeue_slot(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let idx = self.queue[self.head] as usize;
        self.head = (self.head + 1) % MAILBOX_CAP;
        self.count -= 1;
        Some(idx)
    }

    /// Detach only the retired destination's messages. The caller releases
    /// their attachments after dropping the mailbox lock. Filtering preserves
    /// FIFO order for a newer generation already occupying this reusable slot.
    fn retire_destination(
        &mut self,
        endpoint: IpcEndpoint,
    ) -> [Option<Box<Message>>; MAILBOX_CAP] {
        let mut retired = [const { None }; MAILBOX_CAP];
        if self.count > MAILBOX_CAP {
            self.quarantine("ipc mailbox count exceeds capacity during retirement");
            return retired;
        }
        let count = self.count;
        for output in retired.iter_mut().take(count) {
            let Some(slot) = self.dequeue_slot() else {
                break;
            };
            let Some(message) = self.slots.get(slot).and_then(Option::as_ref) else {
                self.quarantine("ipc mailbox retirement points to an empty slot");
                break;
            };
            if message.to == endpoint.thread_id
                && message.to_slot == endpoint.slot
                && message.to_generation == endpoint.generation
            {
                *output = self.take_slot(slot);
                if output.is_none() {
                    break;
                }
            } else if self.enqueue_slot(slot).is_err() {
                self.quarantine("ipc mailbox retirement could not preserve queue");
                break;
            }
        }
        if self.reply_owner == Some((endpoint.thread_id, endpoint.generation)) {
            self.reply_targets.clear();
            self.reply_owner = None;
        }
        retired
    }

    fn push_message(
        &mut self,
        from: u64,
        to: u64,
        to_slot: u16,
        to_generation: u64,
        data: &[u8],
        is_reply: bool,
        expects_reply: bool,
        call_id: u64,
        delivery_flags: u32,
    ) -> Result<(), ()> {
        if data.len() > ipc_max_msg_size() {
            return Err(());
        }
        let slot_idx = match self.alloc_slot() {
            Some(i) => i,
            None => return Err(()),
        };
        let Some(msg) = self.slots[slot_idx].as_deref_mut() else {
            self.quarantine("ipc mailbox allocated slot is missing");
            return Err(());
        };
        msg.from = from;
        msg.to = to;
        msg.to_slot = to_slot;
        msg.to_generation = to_generation;
        msg.is_reply = is_reply;
        msg.expects_reply = expects_reply;
        msg.call_id = call_id;
        msg.len = data.len();
        msg.object_handles = ObjectHandleAttachments::empty();
        msg.object_handles.delivery_flags = delivery_flags;
        if !data.is_empty() {
            msg.data[..data.len()].copy_from_slice(data);
            record_ipc_copy(data.len());
        }
        if self.enqueue_slot(slot_idx).is_err() {
            let _ = self.free_slot(slot_idx);
            return Err(());
        }
        Ok(())
    }

    fn pop_valid_for_receiver_to_user(
        &mut self,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        buf_ptr: u64,
        max_copy: usize,
        accept_object_handles: bool,
    ) -> Result<Option<UserReceive>, u64> {
        while self.count > 0 {
            let slot_idx = self.queue[self.head] as usize;
            let Some(msg) = self
                .slots
                .get_mut(slot_idx)
                .and_then(Option::as_deref_mut)
            else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return Ok(None);
            };
            if msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
            {
                let _ = self.dequeue_slot();
                if !self.free_slot(slot_idx) {
                    return Ok(None);
                }
                continue;
            }
            if !accept_object_handles && !msg.object_handles.is_empty() {
                return Err(EMSGSIZE);
            }

            let copy_len = core::cmp::min(msg.len, max_copy);
            if copy_len > 0 && buf_ptr != 0 {
                crate::syscall::copy_to_user(buf_ptr, &msg.data[..copy_len])?;
                record_ipc_copy(copy_len);
            }

            let receive = UserReceive {
                from: msg.from,
                copy_len,
                expects_reply: msg.expects_reply,
                call_id: msg.call_id,
                object_handles: core::mem::replace(
                    &mut msg.object_handles,
                    ObjectHandleAttachments::empty(),
                ),
            };
            let dequeued = self.dequeue_slot();
            if dequeued != Some(slot_idx) || !self.free_slot(slot_idx) {
                return Ok(None);
            }
            return Ok(Some(receive));
        }
        Ok(None)
    }

    /// 指定送信元からの有効メッセージを1件だけ取り出し、内容を out へコピーする
    fn pop_from_sender_copy(
        &mut self,
        sender: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        out: &mut [u8],
        reply_only: bool,
    ) -> Option<(u64, usize, bool)> {
        if self.count == 0 {
            return None;
        }

        let original = self.count;
        for _ in 0..original {
            let slot_idx = self.dequeue_slot()?;
            let Some(msg) = self.slots[slot_idx].as_deref() else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return None;
            };
            if msg.from != sender
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
                || (reply_only && !msg.is_reply)
            {
                if self.enqueue_slot(slot_idx).is_err() {
                    let _ = self.free_slot(slot_idx);
                    return None;
                }
                continue;
            }

            let copy_len = core::cmp::min(msg.len, out.len());
            if copy_len > 0 {
                out[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                record_ipc_copy(copy_len);
            }
            let from = msg.from;
            let expects_reply = msg.expects_reply;
            if !self.free_slot(slot_idx) {
                return None;
            }
            return Some((from, copy_len, expects_reply));
        }

        None
    }

    fn pop_reply_to_user(
        &mut self,
        expected_sender: u64,
        expected_call_id: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        buf_ptr: u64,
        max_copy: usize,
        accept_object_handles: bool,
    ) -> Result<Option<UserReceive>, u64> {
        if self.count == 0 {
            return Ok(None);
        }

        let original = self.count;
        for _ in 0..original {
            let Some(slot_idx) = self.dequeue_slot() else {
                return Ok(None);
            };
            let Some(msg) = self.slots.get_mut(slot_idx).and_then(Option::as_deref_mut) else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return Ok(None);
            };
            if msg.from != expected_sender
                || msg.call_id != expected_call_id
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
                || !msg.is_reply
            {
                if self.enqueue_slot(slot_idx).is_err() {
                    let _ = self.free_slot(slot_idx);
                    return Ok(None);
                }
                continue;
            }

            if !accept_object_handles && !msg.object_handles.is_empty() {
                if !self.free_slot(slot_idx) {
                    return Ok(None);
                }
                return Err(EMSGSIZE);
            }

            let copy_len = core::cmp::min(msg.len, max_copy);
            if copy_len > 0 && buf_ptr != 0 {
                if let Err(error) = crate::syscall::copy_to_user(buf_ptr, &msg.data[..copy_len]) {
                    if self.enqueue_slot(slot_idx).is_err() {
                        let _ = self.free_slot(slot_idx);
                    }
                    return Err(error);
                }
                record_ipc_copy(copy_len);
            }
            let receive = UserReceive {
                from: msg.from,
                copy_len,
                expects_reply: false,
                call_id: msg.call_id,
                object_handles: core::mem::replace(
                    &mut msg.object_handles,
                    ObjectHandleAttachments::empty(),
                ),
            };
            if !self.free_slot(slot_idx) {
                return Ok(None);
            }
            return Ok(Some(receive));
        }

        Ok(None)
    }

    fn pop_reply_copy(
        &mut self,
        expected_sender: u64,
        expected_call_id: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        output: &mut [u8],
    ) -> Option<(u64, usize)> {
        if self.count == 0 {
            return None;
        }
        let original = self.count;
        for _ in 0..original {
            let slot_idx = self.dequeue_slot()?;
            let Some(msg) = self.slots.get(slot_idx).and_then(Option::as_deref) else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return None;
            };
            if msg.from != expected_sender
                || msg.call_id != expected_call_id
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
                || !msg.is_reply
            {
                if self.enqueue_slot(slot_idx).is_err() {
                    let _ = self.free_slot(slot_idx);
                    return None;
                }
                continue;
            }
            let copy_len = core::cmp::min(msg.len, output.len());
            output[..copy_len].copy_from_slice(&msg.data[..copy_len]);
            let from = msg.from;
            if !self.free_slot(slot_idx) {
                return None;
            }
            record_ipc_copy(copy_len);
            return Some((from, copy_len));
        }
        None
    }

    /// メッセージを積んだ後、待機中スレッドがいれば返して登録を消す
    fn take_waiter(&mut self) -> u64 {
        let w = self.waiter;
        self.waiter = 0;
        w
    }
}

struct MessageCache {
    slots: [Option<Box<Message>>; MESSAGE_CACHE_CAP],
    count: usize,
}

impl MessageCache {
    const fn new() -> Self {
        Self {
            slots: [const { None }; MESSAGE_CACHE_CAP],
            count: 0,
        }
    }

    fn take(&mut self) -> Option<Box<Message>> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match self.slots[self.count].take() {
            Some(message) => Some(message),
            None => {
                self.quarantine("ipc message cache count points to an empty slot");
                None
            }
        }
    }

    fn put(&mut self, message: Box<Message>) -> Result<(), Box<Message>> {
        if self.count >= MESSAGE_CACHE_CAP {
            return Err(message);
        }
        if self.slots[self.count].is_some() {
            self.quarantine("ipc message cache points to an occupied slot");
            return Err(message);
        }
        self.slots[self.count] = Some(message);
        self.count += 1;
        Ok(())
    }

    fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
        for message in self.slots.iter_mut().filter_map(Option::take) {
            drop(wipe_message(message));
        }
        self.count = 0;
    }
}

fn wipe_message(mut message: Box<Message>) -> Box<Message> {
    // Volatile stores do not drop the overwritten value. Release any authority
    // still owned by a discarded message before erasing its reusable storage.
    drop(core::mem::replace(
        &mut message.object_handles,
        ObjectHandleAttachments::empty(),
    ));
    // The volatile replacement keeps message contents from surviving in a
    // reusable kernel heap allocation after the queue releases them.
    unsafe {
        core::ptr::write_volatile(message.as_mut(), Message::empty());
    }
    message
}

fn release_message(message: Box<Message>) {
    let message = wipe_message(message);
    if let Err(message) = MESSAGE_CACHE.lock().put(message) {
        drop(message);
    }
}

fn allocate_message() -> Option<Box<Message>> {
    if let Some(message) = MESSAGE_CACHE.lock().take() {
        return Some(message);
    }
    let layout = Layout::new::<Message>();
    // SAFETY: The returned pointer is checked before it is initialized and
    // converted into a Box with the same global allocator and layout.
    let pointer = unsafe { alloc(layout) }.cast::<Message>();
    if pointer.is_null() {
        return None;
    }
    // SAFETY: `pointer` is non-null, suitably aligned for Message, and owns one
    // allocation of exactly `Layout::new::<Message>()` bytes.
    let message = unsafe {
        pointer.write(Message::empty());
        Box::from_raw(pointer)
    };
    crate::performance::increment(crate::performance::CounterMetric::IpcSendAllocations, 1);
    Some(message)
}

static MESSAGE_CACHE: SpinLock<MessageCache> = SpinLock::new(MessageCache::new());
static MAILBOXES: SpinLock<[Mailbox; MAX_THREADS]> =
    SpinLock::new([const { Mailbox::new() }; MAX_THREADS]);

#[inline]
fn lock_mailboxes() -> SpinLockGuard<'static, [Mailbox; MAX_THREADS]> {
    #[cfg(feature = "performance-instrumentation")]
    let start = crate::performance::timestamp();
    let guard = MAILBOXES.lock();
    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_latency(crate::performance::LatencyMetric::IpcLockWait, start);
    guard
}

/// The caller has published termination and released the thread queue lock.
/// Exact destination filtering also tolerates delayed cleanup after slot reuse.
pub(crate) fn retire_endpoint(endpoint: IpcEndpoint) {
    if (endpoint.slot as usize) < MAX_THREADS {
        let retired = {
            let mut boxes = lock_mailboxes();
            let mailbox = &mut boxes[endpoint.slot as usize];
            let retired = mailbox.retire_destination(endpoint);
            let current = crate::task::thread_slot_index_and_generation_by_u64(endpoint.thread_id);
            if mailbox.waiter == endpoint.thread_id
                && current.is_none_or(|(slot, generation)| {
                    slot == endpoint.slot as usize && generation == endpoint.generation
                })
            {
                mailbox.waiter = 0;
            }
            retired
        };
        for message in retired.into_iter().flatten() {
            release_message(message);
        }
    }
    lifetime::retire(endpoint);
}

/// カーネル内部からIPC送信（ユーザー空間コピー不要）
pub fn send_from_kernel(dest_thread_id: u64, data: &[u8]) -> bool {
    let len = data.len();
    if len > ipc_max_msg_size() {
        return false;
    }
    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return false,
        };
    if idx >= MAX_THREADS {
        return false;
    }
    let sender = crate::task::current_thread_id()
        .and_then(|t| ensure_endpoint_for_thread(t.as_u64()))
        .unwrap_or(0);
    lock_mailboxes().get_mut(idx).map_or(false, |mb| {
        if !endpoint_is_valid(IpcEndpoint {
            thread_id: dest_thread_id,
            slot: idx as u16,
            generation: dest_generation,
        }) {
            return false;
        }
        if mb
            .push_message(
                sender,
                dest_thread_id,
                idx as u16,
                dest_generation,
                data,
                false,
                false,
                0,
                0,
            )
            .is_ok()
        {
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

/// Sends one non-blocking message to an exact provider endpoint identity.
pub(crate) fn send_provider_from_kernel(endpoint: IpcEndpoint, data: &[u8]) -> bool {
    if data.len() > ipc_max_msg_size() || !endpoint_is_valid(endpoint) {
        return false;
    }
    // Release notifications expect no reply. Reuse an existing sender, or the
    // already supported kernel/no-sender value; never allocate endpoint maps
    // while reclaiming a reference under memory pressure.
    let sender = crate::task::current_thread_id()
        .and_then(|thread| endpoint_handle_for_thread(thread.as_u64()))
        .unwrap_or(0);
    let mut mailboxes = lock_mailboxes();
    if !endpoint_is_valid(endpoint) {
        return false;
    }
    let Some(mailbox) = mailboxes.get_mut(endpoint.slot as usize) else {
        return false;
    };
    if mailbox
        .push_message(
            sender,
            endpoint.thread_id,
            endpoint.slot,
            endpoint.generation,
            data,
            false,
            false,
            0,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        )
        .is_err()
    {
        return false;
    }
    let waiter = mailbox.take_waiter();
    drop(mailboxes);
    if waiter != 0 {
        crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
    }
    true
}

/// Performs a synchronous IPC call without copying through userspace buffers.
pub fn call_from_kernel(
    dest_endpoint_handle: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, u64> {
    if request.len() > ipc_max_msg_size() || reply.len() > ipc_max_msg_size() {
        return Err(EINVAL);
    }
    let dest_record = endpoint_record_from_handle(dest_endpoint_handle).ok_or(EINVAL)?;
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return Err(EACCES);
    }
    call_endpoint_from_kernel(
        IpcEndpoint {
            thread_id: dest_record.thread_id,
            slot: dest_record.slot,
            generation: dest_record.generation,
        },
        dest_endpoint_handle,
        request,
        reply,
    )
}

/// Performs a synchronous kernel-originated call against an exact endpoint
/// identity rather than a process-visible endpoint handle.
pub(crate) fn call_provider_from_kernel(
    endpoint: IpcEndpoint,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, u64> {
    if !endpoint_is_valid(endpoint) {
        return Err(super::ESRCH);
    }
    let expected_sender = ensure_endpoint_for_thread(endpoint.thread_id).ok_or(EINVAL)?;
    let mut attachments = ObjectHandleAttachments::empty();
    attachments.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    call_endpoint_with_attachments_from_kernel(endpoint, expected_sender, request, reply, attachments)
}

fn call_endpoint_from_kernel(
    endpoint: IpcEndpoint,
    expected_sender: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, u64> {
    call_endpoint_with_attachments_from_kernel(
        endpoint,
        expected_sender,
        request,
        reply,
        ObjectHandleAttachments::empty(),
    )
}

/// Attach only handles from the authenticated caller's own table, through the
/// same attenuation enforcement as user-originated IPC.
pub(crate) fn call_provider_with_handle_from_kernel(
    endpoint: IpcEndpoint,
    request: &[u8],
    reply: &mut [u8],
    handle: ObjectHandle,
    requested: HandleRights,
) -> Result<usize, u64> {
    if !endpoint_is_valid(endpoint) {
        return Err(super::ESRCH);
    }
    let process_id = crate::syscall::security::current_process_id().ok_or(EINVAL)?;
    let mut attachments = ObjectHandleAttachments::empty();
    attachments.handles[0] = Some(export_object_handle(process_id, handle, requested)?);
    attachments.count = 1;
    attachments.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let expected_sender = ensure_endpoint_for_thread(endpoint.thread_id).ok_or(EINVAL)?;
    call_endpoint_with_attachments_from_kernel(
        endpoint, expected_sender, request, reply, attachments,
    )
}

fn call_endpoint_with_attachments_from_kernel(
    endpoint: IpcEndpoint,
    expected_sender: u64,
    request: &[u8],
    reply: &mut [u8],
    mut attachments: ObjectHandleAttachments,
) -> Result<usize, u64> {
    if request.len() > ipc_max_msg_size() || reply.len() > ipc_max_msg_size() {
        return Err(EINVAL);
    }
    let caller = crate::task::current_thread_id().ok_or(EINVAL)?.as_u64();
    let _lifetime = lifetime::observe(endpoint, crate::task::ThreadId::from_u64(caller))?;
    let sender = ensure_endpoint_for_thread(caller).ok_or(EINVAL)?;
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let (dest_slot, dest_generation) =
        crate::task::thread_slot_index_and_generation_by_u64(endpoint.thread_id)
            .filter(|(slot, generation)| {
                *slot as u16 == endpoint.slot && *generation == endpoint.generation
            })
            .ok_or(EINVAL)?;
    loop {
        if !endpoint_is_valid(endpoint) {
            return Err(super::ESRCH);
        }
        let mut mailboxes = lock_mailboxes();
        if !endpoint_is_valid(endpoint) {
            return Err(super::ESRCH);
        }
        let mailbox = mailboxes.get_mut(dest_slot).ok_or(EINVAL)?;
        if let Some(slot) = mailbox.alloc_slot() {
            let Some(message) = mailbox.slots[slot].as_deref_mut() else {
                mailbox.quarantine("ipc mailbox allocated slot is missing");
                return Err(EIO);
            };
            message.from = sender;
            message.to = endpoint.thread_id;
            message.to_slot = dest_slot as u16;
            message.to_generation = dest_generation;
            message.is_reply = false;
            message.expects_reply = true;
            message.call_id = call_id;
            message.len = request.len();
            message.data[..request.len()].copy_from_slice(request);
            record_ipc_copy(request.len());
            message.object_handles = attachments;
            if mailbox.enqueue_slot(slot).is_err() {
                // Keep ownership while retrying rather than discarding handles.
                attachments = core::mem::replace(
                    &mut mailbox.slots[slot].as_deref_mut().ok_or(EIO)?.object_handles,
                    ObjectHandleAttachments::empty(),
                );
                mailbox.free_slot(slot);
            } else {
                let waiter = mailbox.take_waiter();
                drop(mailboxes);
                if waiter != 0 {
                    crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
                }
                break;
            }
        }
        drop(mailboxes);
        crate::task::yield_now();
    }
    let (caller_slot, caller_generation) =
        crate::task::thread_slot_index_and_generation_by_u64(caller).ok_or(EINVAL)?;
    loop {
        let received = {
            let mut mailboxes = lock_mailboxes();
            let mailbox = mailboxes.get_mut(caller_slot).ok_or(EINVAL)?;
            let received = mailbox.pop_reply_copy(
                expected_sender,
                call_id,
                caller,
                caller_slot as u16,
                caller_generation,
                reply,
            );
            if received.is_none() {
                mailbox.waiter = caller;
            }
            received
        };
        if let Some((_, length)) = received {
            return Ok(length);
        }
        if !endpoint_is_valid(endpoint) {
            let mut mailboxes = lock_mailboxes();
            if mailboxes[caller_slot].waiter == caller {
                mailboxes[caller_slot].waiter = 0;
            }
            return Err(super::ESRCH);
        }
        if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(caller)) {
            crate::task::yield_now();
        } else {
            let mut mailboxes = lock_mailboxes();
            if mailboxes[caller_slot].waiter == caller {
                mailboxes[caller_slot].waiter = 0;
            }
        }
    }
}

fn send_to_thread_id(dest_thread_id: u64, sender_handle: u64, buf_ptr: u64, len: u64) -> u64 {
    send_to_thread_id_with_kind(
        dest_thread_id,
        sender_handle,
        0,
        buf_ptr,
        len,
        false,
        false,
        ObjectHandleAttachments::empty(),
    )
}

fn send_call_to_thread_id(
    dest_thread_id: u64,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    delivery_flags: u32,
) -> u64 {
    let mut attachments = ObjectHandleAttachments::empty();
    attachments.delivery_flags = delivery_flags;
    send_to_thread_id_with_kind(
        dest_thread_id,
        sender_handle,
        call_id,
        buf_ptr,
        len,
        false,
        true,
        attachments,
    )
}

fn send_to_thread_id_with_kind(
    dest_thread_id: u64,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    is_reply: bool,
    expects_reply: bool,
    object_handles: ObjectHandleAttachments,
) -> u64 {
    send_to_thread_id_with_attachments(
        dest_thread_id,
        sender_handle,
        call_id,
        buf_ptr,
        len,
        is_reply,
        expects_reply,
        object_handles,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_to_thread_id_with_attachments(
    dest_thread_id: u64,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    is_reply: bool,
    expects_reply: bool,
    object_handles: ObjectHandleAttachments,
) -> u64 {
    if dest_thread_id == 0 {
        return EINVAL;
    }

    let len = len as usize;
    if len > ipc_max_msg_size() {
        return EINVAL;
    }
    if len > 0 && buf_ptr == 0 {
        return EFAULT;
    }

    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    #[cfg(feature = "performance-instrumentation")]
    let send_start = crate::performance::timestamp();

    // NOTE:
    // - 宛先スロットに加えて世代番号をメッセージへ埋め込む。
    // - これにより、送信先終了後に同一スロットへ別スレッドが再利用されても誤配送されない。
    // - 送信時点と受信時点で世代不一致なら古いメッセージとして破棄される。

    let Some(mut message) = allocate_message() else {
        return EAGAIN;
    };
    message.from = sender_handle;
    message.to = dest_thread_id;
    message.to_slot = idx as u16;
    message.to_generation = dest_generation;
    message.is_reply = is_reply;
    message.expects_reply = expects_reply;
    message.call_id = call_id;
    message.len = len;
    message.object_handles = object_handles;

    // ユーザー空間から、キューが所有する領域へ直接コピーする。
    if len > 0 && buf_ptr != 0 {
        if let Err(err) = crate::syscall::copy_from_user(buf_ptr, &mut message.data[..len]) {
            release_message(message);
            return err;
        }
        record_ipc_copy(len);
    }
    let mut boxes = lock_mailboxes();
    if !endpoint_is_valid(IpcEndpoint {
        thread_id: dest_thread_id,
        slot: idx as u16,
        generation: dest_generation,
    }) {
        drop(boxes);
        release_message(message);
        return super::ESRCH;
    }
    if boxes[idx].enqueue_message(message).is_err() {
        return EAGAIN;
    }
    crate::debug!(
        "[IPC SEND] from={} to={} len={}",
        sender_handle,
        dest_thread_id,
        len
    );
    let waiter = boxes[idx].take_waiter();
    drop(boxes);
    if waiter != 0 {
        crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
    }

    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_latency(
        if len >= 4096 {
            crate::performance::LatencyMetric::IpcFourKilobytes
        } else {
            crate::performance::LatencyMetric::IpcSmallOneWay
        },
        send_start,
    );

    0
}

/// IPC送信
/// arg0: endpoint handle
/// arg1: buf_ptr
/// arg2: len
pub fn send(dest_endpoint_handle: u64, buf_ptr: u64, len: u64) -> u64 {
    let dest_record = match endpoint_record_from_handle(dest_endpoint_handle) {
        Some(record) => record,
        None => return EINVAL,
    };
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return EACCES;
    }
    let dest_thread_id = dest_record.thread_id;
    let sender = match crate::task::current_thread_id() {
        Some(id) => ensure_endpoint_for_thread(id.as_u64()).unwrap_or(EINVAL),
        None => return EINVAL,
    };
    if sender == EINVAL {
        return EINVAL;
    }
    if let Some(sender_record) = endpoint_record_from_handle(sender) {
        if !sender_record.rights.contains(EndpointRights::SEND) {
            return EACCES;
        }
    }

    // capability 強制:
    // IPC で任意スレッドへメッセージを送れると、サービス制御や情報取得が無権限で可能になる。
    // そのため、送信は `ipc.client` または `ipc.server` を持つプロセスに限定する。
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    send_to_thread_id(dest_thread_id, sender, buf_ptr, len)
}

/// Sends one IPC message with rights-restricted process-local object handles.
pub fn send_object_handles(
    dest_endpoint_handle: u64,
    buf_ptr: u64,
    len: u64,
    handles_ptr: u64,
) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let (dest_thread_id, _, delivery_flags) = match resolve_call_destination(dest_endpoint_handle) {
        Ok(destination) => destination,
        Err(error) => return error,
    };
    let sender = match crate::task::current_thread_id() {
        Some(id) => match ensure_endpoint_for_thread(id.as_u64()) {
            Some(handle) => handle,
            None => return EINVAL,
        },
        None => return EINVAL,
    };
    let mut object_handles = match decode_outgoing_object_handles(handles_ptr) {
        Ok(handles) => handles,
        Err(error) => return error,
    };
    object_handles.delivery_flags = delivery_flags;
    send_to_thread_id_with_attachments(
        dest_thread_id,
        sender,
        0,
        buf_ptr,
        len,
        false,
        false,
        object_handles,
    )
}


fn finish_user_receive(
    receiver_thread_id: u64,
    receive: UserReceive,
    object_handles_output: Option<u64>,
) -> Result<(u64, usize, bool), u64> {
    if let Some(output) = object_handles_output {
        install_received_object_handles(receiver_thread_id, receive.object_handles, output)?;
    } else if !receive.object_handles.is_empty() {
        return Err(EMSGSIZE);
    }
    Ok((receive.from, receive.copy_len, receive.expects_reply))
}

fn recv_from_thread_nonblocking(
    receiver_thread_id: u64,
    caller_thread_id: u64,
    buf_ptr: u64,
    max_len: u64,
    object_handles_output: Option<u64>,
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
    let receive = {
        let mut boxes = lock_mailboxes();
        match boxes[idx].pop_valid_for_receiver_to_user(
            receiver_thread_id,
            idx as u16,
            receiver_generation,
            buf_ptr,
            max_copy,
            object_handles_output.is_some(),
        ) {
            Ok(Some(receive)) => {
                if let Some((caller_idx, caller_generation)) =
                    crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                {
                    if caller_idx < MAX_THREADS && receive.expects_reply {
                        boxes[caller_idx].add_reply_target(
                            receive.from, receive.call_id, (caller_thread_id, caller_generation),
                        );
                    }
                }
                receive
            }
            Ok(None) => return EAGAIN,
            Err(error) => return error,
        }
    };
    let (from, copy_len, _) =
        match finish_user_receive(receiver_thread_id, receive, object_handles_output) {
            Ok(result) => result,
            Err(error) => return error,
        };
    crate::debug!(
        "[IPC RECV] tid={} from={} len={}",
        receiver_thread_id,
        from,
        copy_len
    );

    (from << 32) | (copy_len as u64)
}

fn recv_blocking_for_thread(
    receiver_thread_id: u64,
    caller_thread_id: u64,
    buf_ptr: u64,
    max_len: u64,
    object_handles_output: Option<u64>,
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    loop {
        let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
        let recv = {
            let mut boxes = lock_mailboxes();
            match boxes[idx].pop_valid_for_receiver_to_user(
                receiver_thread_id,
                idx as u16,
                receiver_generation,
                buf_ptr,
                max_copy,
                object_handles_output.is_some(),
            ) {
                Ok(Some(receive)) => {
                    if let Some((caller_idx, caller_generation)) =
                        crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                    {
                        if caller_idx < MAX_THREADS && receive.expects_reply {
                            boxes[caller_idx].add_reply_target(
                                receive.from, receive.call_id, (caller_thread_id, caller_generation),
                            );
                        }
                    }
                    Some(receive)
                }
                Ok(None) => {
                    boxes[idx].waiter = caller_thread_id;
                    None
                }
                Err(error) => return error,
            }
        };

        match recv {
            Some(receive) => {
                let (from, copy_len, _) = match finish_user_receive(
                    receiver_thread_id,
                    receive,
                    object_handles_output,
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                crate::debug!(
                    "[IPC RECV] tid={} from={} len={}",
                    receiver_thread_id,
                    from,
                    copy_len
                );
                return (from << 32) | (copy_len as u64);
            }
            None => {
                {
                    let mut boxes = lock_mailboxes();
                    let second_try = boxes[idx].pop_valid_for_receiver_to_user(
                        receiver_thread_id,
                        idx as u16,
                        receiver_generation,
                        buf_ptr,
                        max_copy,
                        object_handles_output.is_some(),
                    );
                    if let Ok(Some(receive)) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        if let Some((caller_idx, caller_generation)) =
                            crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                        {
                            if caller_idx < MAX_THREADS && receive.expects_reply {
                                boxes[caller_idx].add_reply_target(
                                    receive.from, receive.call_id, (caller_thread_id, caller_generation),
                                );
                            }
                        }
                        drop(boxes);
                        let (from, copy_len, _) = match finish_user_receive(
                            receiver_thread_id,
                            receive,
                            object_handles_output,
                        ) {
                            Ok(result) => result,
                            Err(error) => return error,
                        };
                        crate::debug!(
                            "[IPC RECV] tid={} from={} len={}",
                            receiver_thread_id,
                            from,
                            copy_len
                        );
                        return (from << 32) | (copy_len as u64);
                    }
                    if let Err(error) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        return error;
                    }
                }
                if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(
                    caller_thread_id,
                )) {
                    crate::task::yield_now();
                } else {
                    {
                        let mut boxes = lock_mailboxes();
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                    }
                    // A message or another wakeup raced with the transition to sleep.
                    // Retry the queue before registering a new waiter; a blocking receive
                    // must not surface that internal race as an empty result.
                    continue;
                }
            }
        }
    }
}

/// IPC受信
/// arg0: buf_ptr
/// arg1: len
/// 戻り値: (sender_id << 32) | received_len
pub fn recv(buf_ptr: u64, max_len: u64) -> u64 {
    let receiver = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(receiver);
    if let Some(receiver_handle) = endpoint_handle_for_thread(receiver) {
        if let Some(record) = endpoint_record_from_handle(receiver_handle) {
            if !record.rights.contains(EndpointRights::RECV) {
                return EACCES;
            }
        }
    }
    recv_from_thread_nonblocking(receiver, receiver, buf_ptr, max_len, None)
}

/// IPC受信（ブロッキング版）
/// メッセージが届くまでスレッドをスリープして待機する。
/// arg0: buf_ptr
/// arg1: len
pub fn recv_blocking(buf_ptr: u64, max_len: u64) -> u64 {
    let receiver = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(receiver);
    if let Some(receiver_handle) = endpoint_handle_for_thread(receiver) {
        if let Some(record) = endpoint_record_from_handle(receiver_handle) {
            if !record.rights.contains(EndpointRights::RECV) {
                return EACCES;
            }
        }
    }
    recv_blocking_for_thread(receiver, receiver, buf_ptr, max_len, None)
}

/// Receives one message and installs attached generic object handles.
pub fn recv_object_handles(
    buf_ptr: u64,
    max_len: u64,
    handles_ptr: u64,
    blocking: u64,
) -> u64 {
    if handles_ptr == 0 {
        return EFAULT;
    }
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(current);
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len, Some(handles_ptr));
    }
    let target = match resolve_receive_thread(blocking, current) {
        Ok(thread_id) => thread_id,
        Err(error) => return error,
    };
    recv_blocking_for_thread(target, current, buf_ptr, max_len, Some(handles_ptr))
}

/// カーネル内部から、特定送信元のIPCをノンブロッキング受信する
///
/// - メッセージが無い場合は `Ok(None)`
/// - 受信データは `buf` にコピーされる
pub fn recv_from_sender_for_kernel_nonblocking(
    sender_thread_id: u64,
    buf: &mut [u8],
) -> Result<Option<usize>, u64> {
    let receiver = crate::task::current_thread_id().ok_or(EINVAL)?;
    let receiver_u64 = receiver.as_u64();
    let (idx, receiver_generation) =
        crate::task::thread_slot_index_and_generation_by_u64(receiver_u64).ok_or(EINVAL)?;

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return Err(EINVAL);
    }

    let n = {
        let mut boxes = lock_mailboxes();
        boxes[idx]
            .pop_from_sender_copy(
                sender_thread_id,
                receiver_u64,
                idx as u16,
                receiver_generation,
                buf,
                false,
            )
            .map(|(_, n, _)| n)
    };

    Ok(n)
}

/// カーネル内部から、特定送信元のIPCをブロッキング受信する
///
/// - 受信データは `buf` へコピーされる（ユーザー空間検証は行わない）
/// - 指定送信元以外のメッセージはキューに保持されたまま
pub fn recv_blocking_from_sender_for_kernel(
    sender_thread_id: u64,
    buf: &mut [u8],
) -> Result<usize, u64> {
    let receiver = match crate::task::current_thread_id() {
        Some(id) => id,
        None => return Err(EINVAL),
    };
    let receiver_u64 = receiver.as_u64();

    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_u64) {
            Some(v) => v,
            None => return Err(EINVAL),
        };
    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return Err(EINVAL);
    }

    loop {
        let n = {
            let mut boxes = lock_mailboxes();
            match boxes[idx].pop_from_sender_copy(
                sender_thread_id,
                receiver_u64,
                idx as u16,
                receiver_generation,
                buf,
                false,
            ) {
                Some((_, n, _)) => Some(n),
                None => {
                    boxes[idx].waiter = receiver_u64;
                    None
                }
            }
        };

        match n {
            Some(n) => return Ok(n),
            None => {
                {
                    let mut boxes = lock_mailboxes();
                    if let Some((_, n, _)) = boxes[idx].pop_from_sender_copy(
                        sender_thread_id,
                        receiver_u64,
                        idx as u16,
                        receiver_generation,
                        buf,
                        false,
                    ) {
                        if boxes[idx].waiter == receiver_u64 {
                            boxes[idx].waiter = 0;
                        }
                        return Ok(n);
                    }
                }
                if crate::task::sleep_thread_unless_woken(receiver) {
                    crate::task::yield_now();
                } else {
                    let mut boxes = lock_mailboxes();
                    if boxes[idx].waiter == receiver_u64 {
                        boxes[idx].waiter = 0;
                    }
                    return Err(EAGAIN);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::{Mailbox, Message, ObjectHandleAttachments, ReplyTarget};
    use crate::task::{HandleRights, KernelObject, ObjectHandleEntry};

    fn endpoint_entry() -> ObjectHandleEntry {
        ObjectHandleEntry::new(
            KernelObject::IpcEndpoint {
                thread_id: 42,
                slot: 2,
                generation: 7,
            },
            HandleRights::SEND,
        )
    }

    #[test]
    fn mailbox_tracks_more_than_one_deferred_reply() {
        let mut mailbox = Mailbox::new();
        mailbox.add_reply_target(11, 101, (7, 3));
        mailbox.add_reply_target(22, 202, (7, 3));
        mailbox.add_reply_target(11, 101, (7, 3));

        assert_eq!(mailbox.reply_target(11, (7, 3)).unwrap().call_id, 101);
        assert_eq!(mailbox.reply_target(22, (7, 3)).unwrap().call_id, 202);
        assert_eq!(mailbox.reply_targets.len(), 2);

        mailbox.remove_reply_target(ReplyTarget {
            endpoint: 22,
            call_id: 202,
        });
        assert!(mailbox.reply_target(11, (7, 3)).is_some());
        assert!(mailbox.reply_target(22, (7, 3)).is_none());
    }

    #[test]
    fn synchronous_call_only_consumes_its_servers_reply() {
        let mut mailbox = Mailbox::new();
        mailbox
            .push_message(10, 20, 1, 2, &[], true, false, 100, 0)
            .unwrap();
        mailbox
            .push_message(11, 20, 1, 2, &[], true, false, 200, 0)
            .unwrap();

        assert_eq!(
            mailbox
                .pop_reply_to_user(11, 200, 20, 1, 2, 0, 0, false)
                .map(|received| received.map(|value| (value.from, value.copy_len))),
            Ok(Some((11, 0)))
        );
        assert_eq!(
            mailbox
                .pop_reply_to_user(10, 100, 20, 1, 2, 0, 0, false)
                .map(|received| received.map(|value| (value.from, value.copy_len))),
            Ok(Some((10, 0)))
        );
    }

    #[test]
    fn synchronous_call_keeps_stale_reply_from_the_same_server_queued() {
        let mut mailbox = Mailbox::new();
        mailbox
            .push_message(10, 20, 1, 2, &[], true, false, 100, 0)
            .unwrap();
        mailbox
            .push_message(10, 20, 1, 2, &[], true, false, 101, 0)
            .unwrap();

        assert_eq!(
            mailbox
                .pop_reply_to_user(10, 101, 20, 1, 2, 0, 0, false)
                .map(|received| received.map(|value| (value.from, value.copy_len))),
            Ok(Some((10, 0)))
        );
        assert_eq!(
            mailbox
                .pop_reply_to_user(10, 100, 20, 1, 2, 0, 0, false)
                .map(|received| received.map(|value| (value.from, value.copy_len))),
            Ok(Some((10, 0)))
        );
    }

    #[test]
    fn synchronous_call_explicitly_accepts_reply_object_handles() {
        let mut mailbox = Mailbox::new();
        let mut message = Box::new(Message::empty());
        message.from = 10;
        message.to = 20;
        message.to_slot = 1;
        message.to_generation = 2;
        message.is_reply = true;
        message.call_id = 100;
        message.object_handles = ObjectHandleAttachments::empty();
        message.object_handles.count = 1;
        message.object_handles.handles[0] = Some(endpoint_entry());
        mailbox.enqueue_message(message).unwrap();

        let received = mailbox
            .pop_reply_to_user(10, 100, 20, 1, 2, 0, 0, true)
            .unwrap()
            .expect("reply should be received");
        assert_eq!(received.object_handles.count, 1);
        assert_eq!(mailbox.count, 0);
    }

    #[test]
    fn byte_only_call_rejects_and_discards_reply_object_handles() {
        let mut mailbox = Mailbox::new();
        let mut message = Box::new(Message::empty());
        message.from = 10;
        message.to = 20;
        message.to_slot = 1;
        message.to_generation = 2;
        message.is_reply = true;
        message.call_id = 100;
        message.object_handles = ObjectHandleAttachments::empty();
        message.object_handles.count = 1;
        message.object_handles.handles[0] = Some(endpoint_entry());
        mailbox.enqueue_message(message).unwrap();

        assert!(matches!(
            mailbox.pop_reply_to_user(10, 100, 20, 1, 2, 0, 0, false),
            Err(error) if error == mnu_abi::EMSGSIZE
        ));
        assert_eq!(mailbox.count, 0);
    }
}

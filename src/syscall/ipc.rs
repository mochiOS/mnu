//! Native IPC argument validation, usercopy and Handle publication.
use crate::task::{HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub use crate::ipc::*;
mod receive;

pub fn endpoint_alive(handle: u64) -> u64 {
    if handle != 0 && endpoint_record_from_handle(handle).is_some() {
        super::SUCCESS
    } else {
        mnu_abi::status::Error::NotFound.into_raw()
    }
}

pub fn endpoint_owner_process(handle: u64) -> u64 {
    match endpoint_execution_identity(handle) {
        Ok(identity) => identity.process_id,
        Err(error) => error.into_raw(),
    }
}

/// Resolve only a generation-checked IPC endpoint. This grants no object
/// authority and exposes no credentials, parent relationship or service policy.
pub fn endpoint_execution_identity(
    handle: u64,
) -> Result<mnu_abi::ExecutionIdentity, mnu_abi::status::Error> {
    use mnu_abi::status::Error;

    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return Err(Error::AccessDenied);
    }
    let record = endpoint_record_from_handle(handle).ok_or(Error::NotFound)?;
    let process = crate::task::thread_to_process_id(record.thread_id).ok_or(Error::NotFound)?;
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

pub fn create(flags: u64, _reserved: u64) -> u64 {
    use mnu_abi::status::Error;

    if flags != 0 {
        return Error::InvalidArgument.into_raw();
    }
    let thread_id = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return Error::NotReady.into_raw(),
    };
    ensure_endpoint_for_thread(thread_id).unwrap_or_else(|| Error::ResourceUnavailable.into_raw())
}

/// Creates a process-local IPC endpoint handle.
///
/// Unlike the transitional global endpoint number returned by `create`, this
/// value is meaningful only in the caller's object-handle table.
pub fn create_handle(flags: u64, _reserved: u64) -> u64 {
    use mnu_abi::status::Error;

    if flags != 0 {
        return Error::InvalidArgument.into_raw();
    }
    let thread_id = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return Error::NotReady.into_raw(),
    };
    let process_id = match crate::task::thread_to_process_id(thread_id) {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let endpoint = match endpoint_for_thread(thread_id) {
        Some(endpoint) => endpoint,
        None => return Error::NotReady.into_raw(),
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
            .unwrap_or_else(|| Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

fn process_local_endpoint(raw: u64, required: HandleRights) -> Result<IpcEndpoint, u64> {
    use mnu_abi::status::Error;

    let object = crate::syscall::handle::object_native(raw, required).map_err(Error::into_raw)?;
    let KernelObject::IpcEndpoint {
        thread_id,
        slot,
        generation,
    } = object
    else {
        return Err(Error::InvalidArgument.into_raw());
    };
    let endpoint = IpcEndpoint {
        thread_id,
        slot,
        generation,
    };
    endpoint_is_valid(endpoint)
        .then_some(endpoint)
        .ok_or_else(|| Error::NotFound.into_raw())
}

pub(crate) fn resolve_provider_endpoint_native(
    raw: u64,
) -> Result<(u64, u16, u64), mnu_abi::status::Error> {
    use mnu_abi::status::Error;
    let object = crate::syscall::handle::object_native(raw, HandleRights::RECEIVE)?;
    let KernelObject::IpcEndpoint {
        thread_id,
        slot,
        generation,
    } = object
    else {
        return Err(Error::InvalidArgument);
    };
    let endpoint = IpcEndpoint {
        thread_id,
        slot,
        generation,
    };
    if !endpoint_is_valid(endpoint) {
        // A stale generation cannot become valid by waiting or retrying.
        return Err(Error::InvalidArgument);
    }
    Ok((thread_id, slot, generation))
}

/// Identity and delivery semantics resolved once at the userspace boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallDestination {
    endpoint: IpcEndpoint,
    reply_sender: u64,
    delivery_flags: u32,
}

fn resolve_call_destination(raw: u64) -> Result<CallDestination, u64> {
    use mnu_abi::status::Error;

    if raw <= crate::task::PROCESS_MAX_OBJECT_HANDLES as u64 {
        let endpoint = process_local_endpoint(raw, HandleRights::SEND)?;
        let sender_identity = ensure_endpoint_for_thread(endpoint.thread_id)
            .ok_or_else(|| Error::NotReady.into_raw())?;
        return Ok(CallDestination {
            endpoint,
            reply_sender: sender_identity,
            delivery_flags: mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
        });
    }
    // A retained SEND reference is authority for exactly that live endpoint.
    // Only ambient/global addressing requires the process-wide IPC grant.
    // Check it before lookup so unprivileged callers cannot probe global IDs.
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return Err(Error::AccessDenied.into_raw());
    }
    let record = endpoint_record_from_handle(raw).ok_or_else(|| Error::NotFound.into_raw())?;
    if !record.rights.contains(EndpointRights::RECV) {
        return Err(Error::AccessDenied.into_raw());
    }
    Ok(CallDestination {
        endpoint: IpcEndpoint {
            thread_id: record.thread_id,
            slot: record.slot,
            generation: record.generation,
        },
        reply_sender: raw,
        delivery_flags: 0,
    })
}

fn resolve_receive_thread(raw: u64, current_thread_id: u64) -> Result<u64, u64> {
    use mnu_abi::status::Error;

    let thread_id = if raw <= crate::task::PROCESS_MAX_OBJECT_HANDLES as u64 {
        process_local_endpoint(raw, HandleRights::RECEIVE)?.thread_id
    } else {
        let record = endpoint_record_from_handle(raw).ok_or_else(|| Error::NotFound.into_raw())?;
        if !record.rights.contains(EndpointRights::RECV) {
            return Err(Error::AccessDenied.into_raw());
        }
        record.thread_id
    };
    if thread_id != current_thread_id {
        return Err(Error::AccessDenied.into_raw());
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
    use mnu_abi::status::Error;

    let CallDestination {
        endpoint: destination,
        reply_sender: expected_sender,
        delivery_flags,
    } = match resolve_call_destination(dest_endpoint_handle) {
        Ok(destination) => destination,
        Err(error) => return error,
    };
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return Error::NotReady.into_raw(),
    };
    let sender = match ensure_endpoint_for_thread(caller) {
        Some(handle) => handle,
        None => return Error::ResourceUnavailable.into_raw(),
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
            return Error::NotFound.into_raw();
        }
        let status = send_call_to_endpoint(
            destination,
            sender,
            call_id,
            req_ptr,
            req_len,
            delivery_flags,
        );
        if status != mnu_abi::status::Error::NotReady.into_raw() {
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
    use mnu_abi::status::Error;

    if handles_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let CallDestination {
        endpoint: destination,
        reply_sender: expected_sender,
        delivery_flags,
    } = match resolve_call_destination(dest_endpoint_handle) {
        Ok(destination) => destination,
        Err(error) => return error,
    };
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return Error::NotReady.into_raw(),
    };
    let sender = match ensure_endpoint_for_thread(caller) {
        Some(handle) => handle,
        None => return Error::ResourceUnavailable.into_raw(),
    };
    let _lifetime = match lifetime::observe(destination, crate::task::ThreadId::from_u64(caller)) {
        Ok(observation) => observation,
        Err(error) => return error,
    };
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let sent = loop {
        if !endpoint_is_valid(destination) {
            return Error::NotFound.into_raw();
        }
        let mut attachments = match decode_outgoing_object_handles(handles_ptr) {
            Ok(handles) => handles,
            Err(error) => return error,
        };
        attachments.delivery_flags = delivery_flags;
        let status = send_to_endpoint_with_attachments(
            destination,
            sender,
            call_id,
            req_ptr,
            req_len,
            false,
            true,
            attachments,
        );
        if status != mnu_abi::status::Error::NotReady.into_raw() {
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
pub fn reply_object_handles(dest_thread_id: u64, buf_ptr: u64, len: u64, handles_ptr: u64) -> u64 {
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
    use mnu_abi::status::Error;

    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return Error::NotReady.into_raw(),
    };
    let caller_handle = match ensure_endpoint_for_thread(current) {
        Some(handle) => handle,
        None => return Error::ResourceUnavailable.into_raw(),
    };
    let target = {
        let boxes = lock_mailboxes();
        let (idx, generation) = match crate::task::ipc_slot_index_and_generation_by_u64(current) {
            Some(v) => v,
            None => return Error::NotReady.into_raw(),
        };
        if idx >= MAX_THREADS {
            return Error::BackingFailure.into_raw();
        }
        match boxes[idx].reply_target(dest_thread_id, (current, generation)) {
            Some(target) => target,
            None => return Error::AccessDenied.into_raw(),
        }
    };
    if target.endpoint == 0 {
        return Error::BackingFailure.into_raw();
    }
    let record = match endpoint_record_from_handle(target.endpoint) {
        Some(record) => record,
        None => return Error::NotFound.into_raw(),
    };
    let destination = IpcEndpoint {
        thread_id: record.thread_id,
        slot: record.slot,
        generation: record.generation,
    };
    let status = send_to_endpoint_with_attachments(
        destination,
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
        if let Some((idx, _)) = crate::task::ipc_slot_index_and_generation_by_u64(current) {
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
    use mnu_abi::status::Error;

    let (idx, generation) =
        match crate::task::ipc_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(identity) => identity,
            None => return Error::NotReady.into_raw(),
        };
    if idx >= MAX_THREADS || idx > u16::MAX as usize {
        return Error::BackingFailure.into_raw();
    }
    let receive = match receive::wait_message(
        IpcEndpoint {
            thread_id: receiver_thread_id,
            slot: idx as u16,
            generation,
        },
        caller_thread_id,
        buf_ptr,
        core::cmp::min(max_len as usize, ipc_max_msg_size()),
        object_handles_output.is_some(),
        Some((expected_sender, expected_call_id, destination)),
    ) {
        Ok(receive) => receive,
        Err(error) => return error,
    };
    match finish_user_receive(receiver_thread_id, receive, object_handles_output) {
        Ok((from, length, _)) => (from << 32) | length as u64,
        Err(error) => error,
    }
}

fn current_receiver(require_receive: bool) -> Result<u64, u64> {
    use mnu_abi::status::Error;

    let current = crate::task::current_thread_id()
        .ok_or_else(|| Error::NotReady.into_raw())?
        .as_u64();
    let endpoint =
        ensure_endpoint_for_thread(current).ok_or_else(|| Error::ResourceUnavailable.into_raw())?;
    let record = endpoint_record_from_handle(endpoint).ok_or_else(|| Error::NotReady.into_raw())?;
    if require_receive && !record.rights.contains(EndpointRights::RECV) {
        return Err(Error::AccessDenied.into_raw());
    }
    Ok(current)
}

pub fn wait(buf_ptr: u64, max_len: u64, blocking: u64) -> u64 {
    let current = match current_receiver(false) {
        Ok(current) => current,
        Err(error) => return error,
    };
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len, None);
    }
    let target = match resolve_receive_thread(blocking, current) {
        Ok(thread_id) => thread_id,
        Err(error) => return error,
    };
    recv_blocking_for_thread(target, current, buf_ptr, max_len, None)
}

#[inline]
fn decode_outgoing_object_handles(pointer: u64) -> Result<ObjectHandleAttachments, u64> {
    use mnu_abi::status::Error;

    if pointer == 0 {
        return Err(Error::InvalidAddress.into_raw());
    }
    let mut bytes = [0u8; core::mem::size_of::<mnu_abi::IpcObjectHandles>()];
    crate::syscall::copy_from_user_native(pointer, &mut bytes).map_err(Error::into_raw)?;
    let count = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| Error::InvalidArgument.into_raw())?,
    ) as usize;
    let delivery_flags = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| Error::InvalidArgument.into_raw())?,
    );
    if count > MAX_OBJECT_HANDLES || delivery_flags != 0 {
        return Err(Error::InvalidArgument.into_raw());
    }
    let process_id =
        crate::syscall::security::current_process_id().ok_or_else(|| Error::NotReady.into_raw())?;
    let mut attachments = ObjectHandleAttachments::empty();
    for index in 0..count {
        let offset = 8 + index * 16;
        let raw = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::InvalidArgument.into_raw())?,
        );
        let item_reserved = u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| Error::InvalidArgument.into_raw())?,
        );
        let requested_bits = u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| Error::InvalidArgument.into_raw())?,
        );
        if item_reserved != 0 {
            return Err(Error::InvalidArgument.into_raw());
        }
        let handle =
            ObjectHandle::from_raw(raw).ok_or_else(|| Error::InvalidArgument.into_raw())?;
        let requested = HandleRights::from_bits(requested_bits)
            .ok_or_else(|| Error::InvalidArgument.into_raw())?;
        let exported = export_object_handle(process_id, handle, requested)?;
        attachments.handles[index] = Some(exported);
        attachments.count += 1;
    }
    Ok(attachments)
}

fn install_received_object_handles(
    receiver_thread_id: u64,
    mut attachments: ObjectHandleAttachments,
    output_pointer: u64,
) -> Result<(), u64> {
    use mnu_abi::status::Error;

    let count = attachments.count;
    if count > MAX_OBJECT_HANDLES || attachments.handles[..count].iter().any(Option::is_none) {
        return Err(Error::BackingFailure.into_raw());
    }
    let process_id = crate::task::thread_to_process_id(receiver_thread_id)
        .ok_or_else(|| Error::NotReady.into_raw())?;
    let mut reserved = [None; MAX_OBJECT_HANDLES];
    let mut output = [0u8; core::mem::size_of::<mnu_abi::IpcObjectHandles>()];
    output[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    output[4..8].copy_from_slice(&attachments.delivery_flags.to_le_bytes());
    let admission = crate::task::with_process_mut(process_id, |process| {
        for index in 0..count {
            let Some(entry) = attachments.handles[index].take() else {
                return Err(Error::BackingFailure.into_raw());
            };
            let rights = entry.rights().bits();
            let ticket = match process
                .object_handles_mut()
                .reserve(receiver_thread_id, entry)
            {
                Ok(ticket) => ticket,
                Err(entry) => {
                    attachments.handles[index] = Some(entry);
                    return Err(Error::ResourceUnavailable.into_raw());
                }
            };
            reserved[index] = Some(ticket);
            let offset = 8 + index * 16;
            output[offset..offset + 4].copy_from_slice(&ticket.handle().raw().to_le_bytes());
            output[offset + 8..offset + 16].copy_from_slice(&rights.to_le_bytes());
        }
        Ok(())
    })
    .ok_or_else(|| Error::NotReady.into_raw())?;
    if let Err(error) = admission {
        cancel_received_reservations(process_id, &reserved);
        return Err(error);
    }

    // No published selector exists during the potentially faulting usercopy.
    if let Err(error) = crate::syscall::copy_to_user_native(output_pointer, &output) {
        cancel_received_reservations(process_id, &reserved);
        return Err(error.into_raw());
    }
    let publication = crate::task::with_process_mut(process_id, |process| {
        let mut discarded = [const { None }; MAX_OBJECT_HANDLES];
        if reserved[..count].iter().any(Option::is_none)
            || !reserved[..count]
                .iter()
                .flatten()
                .all(|ticket| process.object_handles().is_reserved(*ticket))
        {
            return (Err(Error::BackingFailure.into_raw()), discarded);
        }
        for (index, ticket) in reserved[..count].iter().flatten().copied().enumerate() {
            if !process.object_handles_mut().publish_reserved(ticket) {
                // The whole commit is under one table lock. These entries
                // cannot have been closed or reused by another thread.
                for (slot, published) in reserved[..index].iter().flatten().copied().enumerate() {
                    discarded[slot] = process.object_handles_mut().take_entry(published.handle());
                }
                return (Err(Error::BackingFailure.into_raw()), discarded);
            }
        }
        (Ok(()), discarded)
    })
    .ok_or_else(|| Error::NotReady.into_raw())?;
    let (result, discarded) = publication;
    drop(discarded);
    if result.is_err() {
        cancel_received_reservations(process_id, &reserved);
    }
    result
}

fn cancel_received_reservations(
    process: crate::task::ProcessId,
    tickets: &[Option<crate::task::handle_table::HandleReservation>; MAX_OBJECT_HANDLES],
) {
    let discarded = crate::task::with_process_mut(process, |process| {
        core::array::from_fn::<_, MAX_OBJECT_HANDLES, _>(|index| {
            tickets[index].and_then(|ticket| process.object_handles_mut().cancel_reserved(ticket))
        })
    });
    // Object destructors may enter IPC or other registries.
    drop(discarded);
}

fn send_to_endpoint(destination: IpcEndpoint, sender_handle: u64, buf_ptr: u64, len: u64) -> u64 {
    send_to_endpoint_with_kind(
        destination,
        sender_handle,
        0,
        buf_ptr,
        len,
        false,
        false,
        ObjectHandleAttachments::empty(),
    )
}

fn send_call_to_endpoint(
    destination: IpcEndpoint,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    delivery_flags: u32,
) -> u64 {
    let mut attachments = ObjectHandleAttachments::empty();
    attachments.delivery_flags = delivery_flags;
    send_to_endpoint_with_kind(
        destination,
        sender_handle,
        call_id,
        buf_ptr,
        len,
        false,
        true,
        attachments,
    )
}

fn send_to_endpoint_with_kind(
    destination: IpcEndpoint,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    is_reply: bool,
    expects_reply: bool,
    object_handles: ObjectHandleAttachments,
) -> u64 {
    send_to_endpoint_with_attachments(
        destination,
        sender_handle,
        call_id,
        buf_ptr,
        len,
        is_reply,
        expects_reply,
        object_handles,
    )
}

/// Native send failures distinguish queue pressure (NotReady) from an
/// allocation failure (ResourceUnavailable), which must not be retried as
/// though the receiver merely needed to drain its mailbox.
#[allow(clippy::too_many_arguments)]
fn send_to_endpoint_with_attachments(
    destination: IpcEndpoint,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    is_reply: bool,
    expects_reply: bool,
    object_handles: ObjectHandleAttachments,
) -> u64 {
    use mnu_abi::status::Error;

    if destination.thread_id == 0 {
        return Error::InvalidArgument.into_raw();
    }

    let Ok(len) = usize::try_from(len) else {
        return Error::LimitExceeded.into_raw();
    };
    if len > ipc_max_msg_size() {
        return Error::LimitExceeded.into_raw();
    }
    if len > 0 && buf_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }

    // Keep the exact authority resolved by the caller. Re-resolving a thread
    // ID here could silently bind an old Handle to a replacement generation.
    let idx = destination.slot as usize;

    if idx >= MAX_THREADS {
        return Error::BackingFailure.into_raw();
    }
    if !endpoint_is_valid(destination) {
        return Error::NotFound.into_raw();
    }

    #[cfg(feature = "performance-instrumentation")]
    let send_start = crate::performance::timestamp();

    // NOTE:
    // - 宛先スロットに加えて世代番号をメッセージへ埋め込む。
    // - これにより、送信先終了後に同一スロットへ別スレッドが再利用されても誤配送されない。
    // - 送信時点と受信時点で世代不一致なら古いメッセージとして破棄される。

    let Some(mut message) = allocate_message() else {
        return Error::ResourceUnavailable.into_raw();
    };
    message.from = sender_handle;
    message.to = destination.thread_id;
    message.to_slot = destination.slot;
    message.to_generation = destination.generation;
    message.is_reply = is_reply;
    message.expects_reply = expects_reply;
    message.call_id = call_id;
    message.len = len;
    message.object_handles = object_handles;

    // ユーザー空間から、キューが所有する領域へ直接コピーする。
    if len > 0 && buf_ptr != 0 {
        if let Err(err) = crate::syscall::copy_from_user_native(buf_ptr, &mut message.data[..len]) {
            release_message(message);
            return err.into_raw();
        }
        record_ipc_copy(len);
    }
    let mut boxes = lock_mailboxes();
    if !endpoint_is_valid(destination) {
        drop(boxes);
        release_message(message);
        return Error::NotFound.into_raw();
    }
    if let Err(rejected) = boxes[idx].enqueue_message(message) {
        drop(boxes);
        if let Some(message) = rejected {
            release_message(message);
        }
        return Error::NotReady.into_raw();
    }
    crate::debug!(
        "[IPC SEND] from={} to={} len={}",
        sender_handle,
        destination.thread_id,
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
    use mnu_abi::status::Error;

    let dest_record = match endpoint_record_from_handle(dest_endpoint_handle) {
        Some(record) => record,
        None => return Error::NotFound.into_raw(),
    };
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return Error::AccessDenied.into_raw();
    }
    let destination = IpcEndpoint {
        thread_id: dest_record.thread_id,
        slot: dest_record.slot,
        generation: dest_record.generation,
    };
    let sender = match crate::task::current_thread_id() {
        Some(id) => match ensure_endpoint_for_thread(id.as_u64()) {
            Some(handle) => handle,
            None => return Error::ResourceUnavailable.into_raw(),
        },
        None => return Error::NotReady.into_raw(),
    };
    let Some(sender_record) = endpoint_record_from_handle(sender) else {
        return Error::NotReady.into_raw();
    };
    if !sender_record.rights.contains(EndpointRights::SEND) {
        return Error::AccessDenied.into_raw();
    }

    // capability 強制:
    // IPC で任意スレッドへメッセージを送れると、サービス制御や情報取得が無権限で可能になる。
    // そのため、送信は `ipc.client` または `ipc.server` を持つプロセスに限定する。
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return Error::AccessDenied.into_raw();
    }
    send_to_endpoint(destination, sender, buf_ptr, len)
}

/// Sends one IPC message with rights-restricted process-local object handles.
pub fn send_object_handles(
    dest_endpoint_handle: u64,
    buf_ptr: u64,
    len: u64,
    handles_ptr: u64,
) -> u64 {
    use mnu_abi::status::Error;

    let CallDestination {
        endpoint: destination,
        delivery_flags,
        ..
    } = match resolve_call_destination(dest_endpoint_handle) {
        Ok(destination) => destination,
        Err(error) => return error,
    };
    let sender = match crate::task::current_thread_id() {
        Some(id) => match ensure_endpoint_for_thread(id.as_u64()) {
            Some(handle) => handle,
            None => return Error::ResourceUnavailable.into_raw(),
        },
        None => return Error::NotReady.into_raw(),
    };
    let mut object_handles = match decode_outgoing_object_handles(handles_ptr) {
        Ok(handles) => handles,
        Err(error) => return error,
    };
    object_handles.delivery_flags = delivery_flags;
    send_to_endpoint_with_attachments(
        destination,
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
        return Err(mnu_abi::status::Error::LimitExceeded.into_raw());
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
    use mnu_abi::status::Error;

    let (idx, receiver_generation) =
        match crate::task::ipc_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return Error::NotReady.into_raw(),
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return Error::BackingFailure.into_raw();
    }

    let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
    let receive = match receive::copy_message(
        IpcEndpoint {
            thread_id: receiver_thread_id,
            slot: idx as u16,
            generation: receiver_generation,
        },
        caller_thread_id,
        buf_ptr,
        max_copy,
        object_handles_output.is_some(),
    ) {
        Ok(Some(receive)) => receive,
        Ok(None) => return Error::NotReady.into_raw(),
        Err(error) => return error,
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
    use mnu_abi::status::Error;

    let (idx, generation) =
        match crate::task::ipc_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(identity) => identity,
            None => return Error::NotReady.into_raw(),
        };
    if idx >= MAX_THREADS || idx > u16::MAX as usize {
        return Error::BackingFailure.into_raw();
    }
    let receive = match receive::wait_message(
        IpcEndpoint {
            thread_id: receiver_thread_id,
            slot: idx as u16,
            generation,
        },
        caller_thread_id,
        buf_ptr,
        core::cmp::min(max_len as usize, ipc_max_msg_size()),
        object_handles_output.is_some(),
        None,
    ) {
        Ok(receive) => receive,
        Err(error) => return error,
    };
    match finish_user_receive(receiver_thread_id, receive, object_handles_output) {
        Ok((from, length, _)) => (from << 32) | length as u64,
        Err(error) => error,
    }
}

/// IPC受信
/// arg0: buf_ptr
/// arg1: len
/// 戻り値: (sender_id << 32) | received_len
pub fn recv(buf_ptr: u64, max_len: u64) -> u64 {
    let receiver = match current_receiver(true) {
        Ok(receiver) => receiver,
        Err(error) => return error,
    };
    recv_from_thread_nonblocking(receiver, receiver, buf_ptr, max_len, None)
}

/// IPC受信（ブロッキング版）
/// メッセージが届くまでスレッドをスリープして待機する。
/// arg0: buf_ptr
/// arg1: len
pub fn recv_blocking(buf_ptr: u64, max_len: u64) -> u64 {
    let receiver = match current_receiver(true) {
        Ok(receiver) => receiver,
        Err(error) => return error,
    };
    recv_blocking_for_thread(receiver, receiver, buf_ptr, max_len, None)
}

/// Receives one message and installs attached generic object handles.
pub fn recv_object_handles(buf_ptr: u64, max_len: u64, handles_ptr: u64, blocking: u64) -> u64 {
    if handles_ptr == 0 {
        return mnu_abi::status::Error::InvalidAddress.into_raw();
    }
    let current = match current_receiver(false) {
        Ok(current) => current,
        Err(error) => return error,
    };
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len, Some(handles_ptr));
    }
    let target = match resolve_receive_thread(blocking, current) {
        Ok(thread_id) => thread_id,
        Err(error) => return error,
    };
    recv_blocking_for_thread(target, current, buf_ptr, max_len, Some(handles_ptr))
}

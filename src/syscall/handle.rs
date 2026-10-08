use alloc::sync::Arc;
use alloc::vec;

use crate::task::{HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry, ProviderObject};

use super::{EACCES, EAGAIN, EBADF, EFAULT, EFBIG, EINVAL, EIO, ENOSPC, ENOTSUP, ESRCH, SUCCESS};

pub(crate) fn flush_provider_releases() {
    let releases = crate::task::handle_table::take_provider_releases();
    let mut retry = alloc::vec::Vec::new();
    for release in releases {
        let endpoint = crate::syscall::ipc::IpcEndpoint {
            thread_id: release.endpoint_thread_id,
            slot: release.endpoint_slot,
            generation: release.endpoint_generation,
        };
        if !crate::syscall::ipc::endpoint_is_valid(endpoint) {
            continue;
        }
        let header = mnu_abi::provider::RequestHeader {
            opcode: mnu_abi::provider::OP_RELEASE,
            object_id: release.object_id,
            argument: 0,
            basis: 0,
            length: 0,
            data_length: 0,
        };
        let mut request = [0u8; mnu_abi::provider::REQUEST_HEADER_LEN];
        if header.encode(&[], &mut request).is_ok()
            && !crate::syscall::ipc::send_provider_from_kernel(endpoint, &request)
        {
            retry.push(release);
        }
    }
    crate::task::handle_table::requeue_provider_releases(&mut retry);
}

fn current_process() -> Result<crate::task::ProcessId, u64> {
    crate::syscall::security::current_process_id().ok_or(EINVAL)
}

fn decode_handle(raw: u64) -> Result<ObjectHandle, u64> {
    let raw = u32::try_from(raw).map_err(|_| EBADF)?;
    ObjectHandle::from_raw(raw).ok_or(EBADF)
}

pub(crate) fn object(raw: u64, required_right: HandleRights) -> Result<KernelObject, u64> {
    let process_id = current_process()?;
    let handle = decode_handle(raw)?;
    crate::task::with_process(process_id, |process| {
        let entry = process.object_handles().get(handle).ok_or(EBADF)?;
        if !entry.rights().contains(required_right) {
            return Err(EACCES);
        }
        Ok(entry.object().clone())
    })
    .unwrap_or(Err(EINVAL))
}

pub fn read(raw: u64, buffer: u64, length: u64) -> u64 {
    let object = match object(raw, HandleRights::READ) {
        Ok(object) => object,
        Err(error) => return error,
    };
    match object {
        KernelObject::File(file) => crate::syscall::fs::read_file_handle(&file, buffer, length),
        KernelObject::Provider(provider) => provider_read(&provider, buffer, length),
        _ => EBADF,
    }
}

pub fn write(raw: u64, buffer: u64, length: u64) -> u64 {
    let object = match object(raw, HandleRights::WRITE) {
        Ok(object) => object,
        Err(error) => return error,
    };
    match object {
        KernelObject::File(file) => crate::syscall::fs::write_file_handle(&file, buffer, length),
        KernelObject::Provider(provider) => provider_write(&provider, buffer, length),
        _ => EBADF,
    }
}

pub fn seek(raw: u64, offset: u64, basis: u64) -> u64 {
    let object = match object(raw, HandleRights::SEEK) {
        Ok(object) => object,
        Err(error) => return error,
    };
    let basis = match basis {
        mnu_abi::HANDLE_SEEK_START => crate::syscall::fs::SeekBasis::Start,
        mnu_abi::HANDLE_SEEK_CURRENT => crate::syscall::fs::SeekBasis::Current,
        mnu_abi::HANDLE_SEEK_END => crate::syscall::fs::SeekBasis::End,
        _ => return EINVAL,
    };
    match object {
        KernelObject::File(file) => {
            crate::syscall::fs::seek_file_handle(&file, offset as i64, basis)
        }
        KernelObject::Provider(provider) => provider_seek(&provider, offset as i64, basis),
        _ => EBADF,
    }
}

pub fn options_get(raw: u64) -> u64 {
    let object = match object(raw, HandleRights::CONTROL) {
        Ok(object) => object,
        Err(error) => return error,
    };
    match object {
        KernelObject::File(file) => match crate::syscall::fs::file_handle_options(&file) {
            Ok(options) => options,
            Err(error) => error,
        },
        _ => ENOTSUP,
    }
}

pub fn options_set(raw: u64, options: u64) -> u64 {
    if options & !mnu_abi::HANDLE_OPTIONS_ALL != 0 {
        return EINVAL;
    }
    let object = match object(raw, HandleRights::CONTROL) {
        Ok(object) => object,
        Err(error) => return error,
    };
    match object {
        KernelObject::File(file) => {
            match crate::syscall::fs::set_file_handle_options(&file, options) {
                Ok(()) => SUCCESS,
                Err(error) => error,
            }
        }
        _ => ENOTSUP,
    }
}

fn provider_endpoint(provider: &ProviderObject) -> crate::syscall::ipc::IpcEndpoint {
    crate::syscall::ipc::IpcEndpoint {
        thread_id: provider.endpoint_thread_id,
        slot: provider.endpoint_slot,
        generation: provider.endpoint_generation,
    }
}

fn provider_call(
    provider: &ProviderObject,
    request_header: mnu_abi::provider::RequestHeader,
    request_data: &[u8],
    response_storage: &mut [u8],
) -> Result<(mnu_abi::provider::ResponseHeader, usize), u64> {
    let mut request = vec![0u8; mnu_abi::provider::REQUEST_HEADER_LEN + request_data.len()];
    let request_len = request_header
        .encode(request_data, &mut request)
        .map_err(|_| EINVAL)?;
    let response_len = crate::syscall::ipc::call_provider_from_kernel(
        provider_endpoint(provider),
        &request[..request_len],
        response_storage,
    )?;
    let (response, data) =
        mnu_abi::provider::ResponseHeader::decode(response_storage.get(..response_len).ok_or(EIO)?)
            .map_err(|_| EIO)?;
    if response.opcode != request_header.opcode || response.object_id != provider.object_id {
        return Err(EIO);
    }
    if response.status != 0 {
        return Err(response.status as u64);
    }
    Ok((response, data.len()))
}

fn provider_read(provider: &ProviderObject, buffer: u64, length: u64) -> u64 {
    let length = match usize::try_from(length) {
        Ok(length) => length,
        Err(_) => return EINVAL,
    };
    let mut total = 0usize;
    let mut response_storage =
        vec![0u8; mnu_abi::provider::RESPONSE_HEADER_LEN + mnu_abi::provider::MAX_DATA_LEN];
    while total < length {
        let chunk = (length - total).min(mnu_abi::provider::MAX_DATA_LEN);
        let request = mnu_abi::provider::RequestHeader {
            opcode: mnu_abi::provider::OP_READ,
            object_id: provider.object_id,
            argument: 0,
            basis: 0,
            length: chunk as u32,
            data_length: 0,
        };
        let (response, data_len) =
            match provider_call(provider, request, &[], &mut response_storage) {
                Ok(response) => response,
                Err(error) => return if total == 0 { error } else { total as u64 },
            };
        if response.value as usize != data_len || data_len > chunk {
            return if total == 0 { EIO } else { total as u64 };
        }
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => return if total == 0 { EINVAL } else { total as u64 },
        };
        if let Err(error) = crate::syscall::copy_to_user(
            address,
            &response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN
                ..mnu_abi::provider::RESPONSE_HEADER_LEN + data_len],
        ) {
            return if total == 0 { error } else { total as u64 };
        }
        total += data_len;
        if data_len < chunk {
            break;
        }
    }
    total as u64
}

fn provider_write(provider: &ProviderObject, buffer: u64, length: u64) -> u64 {
    let length = match usize::try_from(length) {
        Ok(length) => length,
        Err(_) => return EINVAL,
    };
    let mut total = 0usize;
    let mut data = vec![0u8; mnu_abi::provider::MAX_DATA_LEN];
    let mut response_storage = vec![0u8; mnu_abi::provider::RESPONSE_HEADER_LEN];
    while total < length {
        let chunk = (length - total).min(data.len());
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => return if total == 0 { EINVAL } else { total as u64 },
        };
        if let Err(error) = crate::syscall::copy_from_user(address, &mut data[..chunk]) {
            return if total == 0 { error } else { total as u64 };
        }
        let request = mnu_abi::provider::RequestHeader {
            opcode: mnu_abi::provider::OP_WRITE,
            object_id: provider.object_id,
            argument: 0,
            basis: 0,
            length: chunk as u32,
            data_length: chunk as u32,
        };
        let (response, data_len) =
            match provider_call(provider, request, &data[..chunk], &mut response_storage) {
                Ok(response) => response,
                Err(error) => return if total == 0 { error } else { total as u64 },
            };
        let written = match usize::try_from(response.value) {
            Ok(written) if data_len == 0 && written <= chunk => written,
            _ => return if total == 0 { EIO } else { total as u64 },
        };
        total += written;
        if written < chunk {
            break;
        }
    }
    total as u64
}

fn provider_seek_result(
    provider: &ProviderObject,
    offset: i64,
    basis: crate::syscall::fs::SeekBasis,
) -> Result<u64, u64> {
    let basis = match basis {
        crate::syscall::fs::SeekBasis::Start => mnu_abi::HANDLE_SEEK_START,
        crate::syscall::fs::SeekBasis::Current => mnu_abi::HANDLE_SEEK_CURRENT,
        crate::syscall::fs::SeekBasis::End => mnu_abi::HANDLE_SEEK_END,
    };
    let request = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_SEEK,
        object_id: provider.object_id,
        argument: offset,
        basis,
        length: 0,
        data_length: 0,
    };
    let mut response_storage = [0u8; mnu_abi::provider::RESPONSE_HEADER_LEN];
    match provider_call(provider, request, &[], &mut response_storage) {
        Ok((response, 0)) => Ok(response.value),
        Ok(_) => Err(EIO),
        Err(error) => Err(error),
    }
}

fn provider_seek(
    provider: &ProviderObject,
    offset: i64,
    basis: crate::syscall::fs::SeekBasis,
) -> u64 {
    provider_seek_result(provider, offset, basis).unwrap_or_else(|error| error)
}

/// Reads one seekable object into kernel-owned storage without exposing any
/// filesystem path or provider identifier to the caller.
pub(crate) fn read_all(raw: u64, maximum_length: usize) -> Result<alloc::vec::Vec<u8>, u64> {
    let object = object(raw, HandleRights::READ.union(HandleRights::SEEK))?;
    let KernelObject::Provider(provider) = object else {
        return Err(ENOTSUP);
    };
    let length = provider_seek_result(&provider, 0, crate::syscall::fs::SeekBasis::End)?;
    let length = usize::try_from(length).map_err(|_| EFBIG)?;
    if length > maximum_length {
        return Err(EFBIG);
    }
    provider_seek_result(&provider, 0, crate::syscall::fs::SeekBasis::Start)?;
    let mut output = alloc::vec![0u8; length];
    let mut offset = 0usize;
    let mut response_storage = alloc::vec![
        0u8;
        mnu_abi::provider::RESPONSE_HEADER_LEN + mnu_abi::provider::MAX_DATA_LEN
    ];
    while offset < output.len() {
        let chunk = (output.len() - offset).min(mnu_abi::provider::MAX_DATA_LEN);
        let request = mnu_abi::provider::RequestHeader {
            opcode: mnu_abi::provider::OP_READ,
            object_id: provider.object_id,
            argument: 0,
            basis: 0,
            length: chunk as u32,
            data_length: 0,
        };
        let (response, data_len) = provider_call(&provider, request, &[], &mut response_storage)?;
        if response.value as usize != data_len || data_len == 0 || data_len > chunk {
            return Err(EIO);
        }
        output[offset..offset + data_len].copy_from_slice(
            &response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN
                ..mnu_abi::provider::RESPONSE_HEADER_LEN + data_len],
        );
        offset += data_len;
    }
    Ok(output)
}

pub fn provider_object_create(endpoint: u64, object_id: u64, requested_rights: u64) -> u64 {
    // Object IDs are returned directly by ProviderObjectIdentify, so keep the
    // syscall's negative range unambiguous.
    if object_id > i64::MAX as u64 {
        return EINVAL;
    }
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) => rights,
        None => return EINVAL,
    };
    let (endpoint_thread_id, endpoint_slot, endpoint_generation) =
        match crate::syscall::ipc::resolve_provider_endpoint(endpoint) {
            Ok(endpoint) => endpoint,
            Err(error) => return error,
        };
    let object = KernelObject::Provider(Arc::new(ProviderObject {
        endpoint_thread_id,
        endpoint_slot,
        endpoint_generation,
        object_id,
    }));
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(object, rights))
            .map(|handle| handle.raw() as u64)
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(EINVAL)
}

/// Returns the opaque identifier of a provider object only to the exact
/// endpoint thread that created it.
pub fn provider_object_identify(raw: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let current = match crate::task::current_thread_id()
        .and_then(|thread| crate::syscall::ipc::endpoint_for_thread(thread.as_u64()))
    {
        Some(endpoint) => endpoint,
        None => return EINVAL,
    };
    crate::task::with_process(process_id, |process| {
        let Some(entry) = process.object_handles().get(handle) else {
            return EBADF;
        };
        let KernelObject::Provider(provider) = entry.object() else {
            return EBADF;
        };
        if provider.endpoint_thread_id != current.thread_id
            || provider.endpoint_slot != current.slot
            || provider.endpoint_generation != current.generation
        {
            return EACCES;
        }
        provider.object_id
    })
    .unwrap_or(EINVAL)
}

pub fn close(raw: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        if !process.object_handles_mut().close(handle) {
            return EBADF;
        }
        process.launch_context_mut().remove_handle(handle);
        SUCCESS
    })
    .unwrap_or(EINVAL)
}

pub fn duplicate(raw: u64, requested_rights: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) => rights,
        None => return EINVAL,
    };
    crate::task::with_process_mut(process_id, |process| {
        let Some(source) = process.object_handles().get(handle) else {
            return EBADF;
        };
        if !source.rights().contains(HandleRights::DUPLICATE) || !source.rights().contains(rights) {
            return EACCES;
        }
        match process
            .object_handles_mut()
            .duplicate_restricted(handle, rights)
        {
            Some(duplicate) => duplicate.raw() as u64,
            None => ENOSPC,
        }
    })
    .unwrap_or(EINVAL)
}

/// Compares two process-local handles without disclosing a globally reusable
/// object identifier. Possession of both valid handles is sufficient.
pub fn same_object(left_raw: u64, right_raw: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let left = match decode_handle(left_raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let right = match decode_handle(right_raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    crate::task::with_process(process_id, |process| {
        let Some(left) = process.object_handles().get(left) else {
            return EBADF;
        };
        let Some(right) = process.object_handles().get(right) else {
            return EBADF;
        };
        u64::from(left.object().is_same_object(right.object()))
    })
    .unwrap_or(EINVAL)
}

const PROCESS_HANDLE_RIGHTS: HandleRights = HandleRights::WAIT
    .union(HandleRights::DUPLICATE)
    .union(HandleRights::TRANSFER);

const PROCESS_ADMIN_HANDLE_RIGHTS: HandleRights = PROCESS_HANDLE_RIGHTS.union(HandleRights::SIGNAL);

fn insert_process_handle(target: crate::task::ProcessId, rights: HandleRights) -> u64 {
    let Some(target_object) = crate::task::with_process(target, |process| process.process_object())
    else {
        return ESRCH;
    };
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Process(target_object),
                rights,
            ))
            .map(|handle| handle.raw() as u64)
            .unwrap_or(ENOSPC)
    })
    .unwrap_or(EINVAL)
}

/// Creates a process handle for the process owning an authenticated IPC
/// endpoint. No caller-supplied process identifier is accepted.
pub fn process_open(endpoint: u64, requested_rights: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return EACCES;
    }
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) if PROCESS_HANDLE_RIGHTS.contains(rights) => rights,
        _ => return EINVAL,
    };
    let Some(thread_id) = crate::syscall::ipc::resolve_endpoint_handle(endpoint) else {
        return EINVAL;
    };
    let Some(target) = crate::task::thread_to_process_id(thread_id) else {
        return ESRCH;
    };
    insert_process_handle(target, rights)
}

/// Creates a native handle for a process identifier. Process identifiers are
/// generic kernel identities; requested control rights are capability-gated.
pub fn process_open_by_id(process_id: u64, requested_rights: u64) -> u64 {
    if process_id == 0 {
        return EINVAL;
    }
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return EACCES;
    }
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) if PROCESS_ADMIN_HANDLE_RIGHTS.contains(rights) => rights,
        _ => return EINVAL,
    };
    if rights.contains(HandleRights::SIGNAL)
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::ProcessKill,
        ])
    {
        return EACCES;
    }
    insert_process_handle(crate::task::ProcessId::from_u64(process_id), rights)
}

fn process_status_for(raw: u64) -> Result<mnu_abi::ProcessStatus, u64> {
    let object = object(raw, HandleRights::WAIT)?;
    let KernelObject::Process(process) = object else {
        return Err(EBADF);
    };
    let exited = process.is_exited();
    Ok(mnu_abi::ProcessStatus {
        process_id: process.id().as_u64(),
        state: if exited {
            mnu_abi::PROCESS_STATE_EXITED
        } else {
            mnu_abi::PROCESS_STATE_RUNNING
        },
        reserved: 0,
        exit_code: process.exit_code(),
    })
}

fn write_process_status(output: u64, status: mnu_abi::ProcessStatus) -> u64 {
    if output == 0 {
        return EINVAL;
    }
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&status as *const mnu_abi::ProcessStatus).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ProcessStatus>(),
        )
    };
    crate::syscall::copy_to_user(output, bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(|error| error)
}

pub fn process_status(raw: u64, output: u64) -> u64 {
    match process_status_for(raw) {
        Ok(status) => write_process_status(output, status),
        Err(error) => error,
    }
}

/// Waits until the process exits. `deadline_nanoseconds` is an absolute
/// monotonic-clock value; zero polls and `u64::MAX` waits indefinitely.
pub fn process_wait(raw: u64, deadline_nanoseconds: u64, output: u64) -> u64 {
    let process_id = match object(raw, HandleRights::WAIT) {
        Ok(KernelObject::Process(process)) => process.id(),
        Ok(_) => return EBADF,
        Err(error) => return error,
    };
    let current = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return EINVAL,
    };
    let deadline_tick = if matches!(
        deadline_nanoseconds,
        mnu_abi::PROCESS_WAIT_POLL | mnu_abi::PROCESS_WAIT_INFINITE
    ) {
        deadline_nanoseconds
    } else {
        crate::syscall::time::monotonic_deadline_tick(deadline_nanoseconds)
    };
    loop {
        crate::syscall::time::disarm_thread_deadline(current);
        let status = match process_status_for(raw) {
            Ok(status) => status,
            Err(error) => return error,
        };
        if status.state == mnu_abi::PROCESS_STATE_EXITED {
            crate::task::remove_process_exit_waiter(current, process_id);
            crate::syscall::time::disarm_thread_deadline(current);
            return write_process_status(output, status);
        }
        if deadline_nanoseconds == mnu_abi::PROCESS_WAIT_POLL
            || (deadline_nanoseconds != mnu_abi::PROCESS_WAIT_INFINITE
                && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds)
        {
            crate::task::remove_process_exit_waiter(current, process_id);
            crate::syscall::time::disarm_thread_deadline(current);
            return EAGAIN;
        }
        if !crate::task::register_process_exit_waiter(current, process_id) {
            return EAGAIN;
        }

        // Recheck after registration so an exit racing with registration
        // cannot be missed.
        let status = match process_status_for(raw) {
            Ok(status) => status,
            Err(error) => {
                crate::task::remove_process_exit_waiter(current, process_id);
                crate::syscall::time::disarm_thread_deadline(current);
                return error;
            }
        };
        if status.state == mnu_abi::PROCESS_STATE_EXITED {
            crate::task::remove_process_exit_waiter(current, process_id);
            crate::syscall::time::disarm_thread_deadline(current);
            return write_process_status(output, status);
        }

        if deadline_nanoseconds != mnu_abi::PROCESS_WAIT_INFINITE
            && !crate::syscall::time::arm_thread_deadline(current, deadline_tick)
        {
            crate::task::remove_process_exit_waiter(current, process_id);
            return EAGAIN;
        }
        let _ = crate::task::sleep_thread_unless_woken(current);
        crate::task::yield_now();
        crate::task::remove_process_exit_waiter(current, process_id);
    }
}

#[derive(Clone)]
enum WaitTarget {
    Process(crate::task::ProcessId),
    IpcEndpoint(crate::syscall::ipc::IpcEndpoint),
    Stream(Arc<crate::task::FileHandle>),
}

fn wait_item_signal(item: &mut mnu_abi::HandleWaitItem) -> Result<(WaitTarget, bool), u64> {
    if item.reserved != 0 || item.interests == 0 {
        return Err(EINVAL);
    }
    let object = object(u64::from(item.handle), HandleRights::WAIT)?;
    match object {
        KernelObject::Process(process) => {
            if item.interests & !mnu_abi::HANDLE_SIGNAL_TERMINATED != 0 {
                return Err(EINVAL);
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
        KernelObject::IpcEndpoint {
            thread_id,
            slot,
            generation,
        } => {
            if item.interests & !mnu_abi::HANDLE_SIGNAL_READABLE != 0 {
                return Err(EINVAL);
            }
            let endpoint = crate::syscall::ipc::IpcEndpoint {
                thread_id,
                slot,
                generation,
            };
            let readable = crate::syscall::ipc::endpoint_wait_ready(endpoint)?;
            item.observed = if readable {
                mnu_abi::HANDLE_SIGNAL_READABLE
            } else {
                0
            };
            Ok((WaitTarget::IpcEndpoint(endpoint), readable))
        }
        KernelObject::File(file) => {
            let supported = mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            if item.interests & !supported != 0 {
                return Err(EINVAL);
            }
            let signals = crate::syscall::fs::stream_signals(&file)?;
            item.observed = signals & item.interests;
            Ok((WaitTarget::Stream(file), item.observed != 0))
        }
        _ => Err(ENOTSUP),
    }
}

fn remove_endpoint_waiters(
    waiter: crate::task::ThreadId,
    endpoints: &[crate::syscall::ipc::IpcEndpoint],
) {
    for endpoint in endpoints {
        crate::syscall::ipc::remove_endpoint_waiter(*endpoint, waiter);
    }
}

fn remove_stream_waiters(waiter: crate::task::ThreadId, streams: &[usize]) {
    for stream in streams {
        crate::syscall::fs::remove_stream_waiter(*stream, waiter);
    }
}

fn copy_wait_items_to_user(items_ptr: u64, items: &[mnu_abi::HandleWaitItem]) -> Result<(), u64> {
    let bytes = unsafe {
        core::slice::from_raw_parts(items.as_ptr().cast::<u8>(), core::mem::size_of_val(items))
    };
    crate::syscall::copy_to_user(items_ptr, bytes)
}

/// Waits until one of the supplied process-local object handles observes an
/// interested native signal. The return value is the ready item's index.
/// `deadline_nanoseconds` is an absolute monotonic-clock value; zero polls and
/// `u64::MAX` waits indefinitely.
pub fn wait_many(items_ptr: u64, count: u64, deadline_nanoseconds: u64) -> u64 {
    let count = match usize::try_from(count) {
        Ok(count) if count <= mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS => count,
        _ => return EINVAL,
    };
    let byte_len = match count.checked_mul(core::mem::size_of::<mnu_abi::HandleWaitItem>()) {
        Some(length) => length,
        None => return EINVAL,
    };
    if byte_len != 0 && !crate::syscall::validate_user_ptr(items_ptr, byte_len as u64) {
        return EFAULT;
    }
    let mut items = alloc::vec![mnu_abi::HandleWaitItem::default(); count];
    if byte_len != 0 {
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(items.as_mut_ptr().cast::<u8>(), byte_len) };
        if let Err(error) = crate::syscall::copy_from_user(items_ptr, bytes) {
            return error;
        }
    }
    let current = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return EINVAL,
    };
    let mut registered_endpoints = alloc::vec::Vec::new();
    let mut registered_streams = alloc::vec::Vec::new();
    let deadline_tick = if matches!(
        deadline_nanoseconds,
        mnu_abi::HANDLE_WAIT_POLL | mnu_abi::HANDLE_WAIT_INFINITE
    ) {
        deadline_nanoseconds
    } else {
        crate::syscall::time::monotonic_deadline_tick(deadline_nanoseconds)
    };

    loop {
        crate::task::remove_process_exit_waiters(current);
        remove_endpoint_waiters(current, &registered_endpoints);
        remove_stream_waiters(current, &registered_streams);
        registered_endpoints.clear();
        registered_streams.clear();
        crate::syscall::time::disarm_thread_deadline(current);
        let mut targets = alloc::vec::Vec::with_capacity(items.len());
        let mut ready = None;
        for (index, item) in items.iter_mut().enumerate() {
            match wait_item_signal(item) {
                Ok((_, true)) if ready.is_none() => ready = Some(index),
                Ok((target, _)) => {
                    targets.push(target);
                }
                Err(error) => return error,
            }
        }
        if let Some(index) = ready {
            return match copy_wait_items_to_user(items_ptr, &items) {
                Ok(()) => index as u64,
                Err(error) => error,
            };
        }
        if deadline_nanoseconds == mnu_abi::HANDLE_WAIT_POLL
            || (deadline_nanoseconds != mnu_abi::HANDLE_WAIT_INFINITE
                && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds)
        {
            if items.is_empty() {
                return EAGAIN;
            }
            return match copy_wait_items_to_user(items_ptr, &items) {
                Ok(()) => EAGAIN,
                Err(error) => error,
            };
        }
        for target in targets {
            match target {
                WaitTarget::Process(process_id) => {
                    if !crate::task::register_process_exit_waiter(current, process_id) {
                        crate::task::remove_process_exit_waiters(current);
                        remove_endpoint_waiters(current, &registered_endpoints);
                        remove_stream_waiters(current, &registered_streams);
                        return EAGAIN;
                    }
                }
                WaitTarget::IpcEndpoint(endpoint) => {
                    if let Err(error) =
                        crate::syscall::ipc::register_endpoint_waiter(endpoint, current)
                    {
                        crate::task::remove_process_exit_waiters(current);
                        remove_endpoint_waiters(current, &registered_endpoints);
                        remove_stream_waiters(current, &registered_streams);
                        return error;
                    }
                    registered_endpoints.push(endpoint);
                }
                WaitTarget::Stream(stream) => {
                    match crate::syscall::fs::register_stream_waiter(&stream, current) {
                        Ok(stream_id) => registered_streams.push(stream_id),
                        Err(error) => {
                            crate::task::remove_process_exit_waiters(current);
                            remove_endpoint_waiters(current, &registered_endpoints);
                            remove_stream_waiters(current, &registered_streams);
                            return error;
                        }
                    }
                }
            }
        }
        if deadline_nanoseconds != mnu_abi::HANDLE_WAIT_INFINITE
            && !crate::syscall::time::arm_thread_deadline(current, deadline_tick)
        {
            crate::task::remove_process_exit_waiters(current);
            remove_endpoint_waiters(current, &registered_endpoints);
            remove_stream_waiters(current, &registered_streams);
            return EAGAIN;
        }

        // Recheck after waiter registration so exits racing with registration
        // cannot be missed. A pending wakeup prevents sleeping in that case.
        let mut became_ready = false;
        for item in &mut items {
            match wait_item_signal(item) {
                Ok((_, is_ready)) => became_ready |= is_ready,
                Err(error) => {
                    crate::task::remove_process_exit_waiters(current);
                    remove_endpoint_waiters(current, &registered_endpoints);
                    remove_stream_waiters(current, &registered_streams);
                    crate::syscall::time::disarm_thread_deadline(current);
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

pub fn process_resume(raw: u64) -> u64 {
    let object = match object(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error,
    };
    let KernelObject::Process(process) = object else {
        return EBADF;
    };
    let process_id = process.id();
    if crate::task::with_process(process_id, |_| ()).is_none() {
        return ESRCH;
    }
    let mut threads = alloc::vec::Vec::new();
    crate::task::for_each_thread(|thread| {
        if thread.process_id() == process_id {
            threads.push(thread.id());
        }
    });
    if threads.is_empty() {
        return ESRCH;
    }
    for thread in threads {
        crate::task::wake_thread(thread);
    }
    SUCCESS
}

pub fn process_terminate(raw: u64, exit_code: u64) -> u64 {
    let object = match object(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error,
    };
    let KernelObject::Process(process) = object else {
        return EBADF;
    };
    let process_id = process.id();
    if crate::task::with_process(process_id, |_| ()).is_none() {
        return ESRCH;
    }
    if crate::syscall::security::current_process_id() == Some(process_id) {
        crate::task::scheduler::exit_current_process(exit_code as i32);
    }
    let mut threads = alloc::vec::Vec::new();
    crate::task::for_each_thread(|thread| {
        if thread.process_id() == process_id {
            threads.push(thread.id());
        }
    });
    for thread in threads {
        crate::task::terminate_thread(thread);
    }
    crate::task::release_process_mmio_mappings(process_id);
    crate::task::release_process_dma_buffers(process_id);
    crate::task::mark_process_exited(process_id, exit_code);
    SUCCESS
}

pub fn launch_get(key: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    crate::task::with_process(process_id, |process| {
        let Some(handle) = process.launch_context().get(key) else {
            return EBADF;
        };
        if process.object_handles().get(handle).is_none() {
            return EBADF;
        }
        handle.raw() as u64
    })
    .unwrap_or(EINVAL)
}

/// Associates one of the caller's existing object handles with an opaque
/// process-context key, replacing the previous association for that key. The
/// kernel assigns no meaning to either the key or the object.
pub fn context_handle_set(key: u64, raw: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        if process.object_handles().get(handle).is_none() {
            return EBADF;
        }
        if !process.launch_context_mut().set(key, handle) {
            return ENOSPC;
        }
        SUCCESS
    })
    .unwrap_or(EINVAL)
}

pub fn context_handle_remove(key: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        process.launch_context_mut().take(key);
        SUCCESS
    })
    .unwrap_or(EINVAL)
}

pub fn context_value_set(key: u64, value: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        if !process.launch_context_mut().set_value(key, value) {
            return ENOSPC;
        }
        SUCCESS
    })
    .unwrap_or(EINVAL)
}

pub fn context_value_remove(key: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    crate::task::with_process_mut(process_id, |process| {
        process.launch_context_mut().remove_value(key);
        SUCCESS
    })
    .unwrap_or(EINVAL)
}

pub fn rights_get(raw: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    crate::task::with_process(process_id, |process| {
        process
            .object_handles()
            .get(handle)
            .map(|entry| entry.rights().bits())
            .unwrap_or(EBADF)
    })
    .unwrap_or(EINVAL)
}

/// Creates a native unidirectional byte stream as two object handles.
/// Descriptor numbering and POSIX descriptor flags are intentionally left to
/// user space.
pub fn stream_pair_create(output: u64) -> u64 {
    if output == 0 {
        return EFAULT;
    }
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let Some(stream_id) = crate::syscall::fs::alloc_stream_state() else {
        return ENOSPC;
    };
    let read = KernelObject::File(Arc::new(crate::task::FileHandle::new_pipe_read(stream_id)));
    let write = KernelObject::File(Arc::new(crate::task::FileHandle::new_pipe_write(stream_id)));
    let handles = crate::task::with_process_mut(process_id, |process| {
        let read = process.object_handles_mut().insert(ObjectHandleEntry::new(
            read,
            HandleRights::READ
                .union(HandleRights::WAIT)
                .union(HandleRights::CONTROL)
                .union(HandleRights::DUPLICATE)
                .union(HandleRights::TRANSFER),
        ));
        let Some(read) = read else {
            return None;
        };
        let write = process.object_handles_mut().insert(ObjectHandleEntry::new(
            write,
            HandleRights::WRITE
                .union(HandleRights::WAIT)
                .union(HandleRights::CONTROL)
                .union(HandleRights::DUPLICATE)
                .union(HandleRights::TRANSFER),
        ));
        let Some(write) = write else {
            process.object_handles_mut().close(read);
            return None;
        };
        Some((read, write))
    })
    .flatten();
    let Some((read, write)) = handles else {
        return ENOSPC;
    };
    let pair = mnu_abi::StreamPair {
        read: read.raw(),
        write: write.raw(),
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&pair as *const mnu_abi::StreamPair).cast::<u8>(),
            core::mem::size_of::<mnu_abi::StreamPair>(),
        )
    };
    if let Err(error) = crate::syscall::copy_to_user(output, bytes) {
        let _ = crate::task::with_process_mut(process_id, |process| {
            process.object_handles_mut().close(read);
            process.object_handles_mut().close(write);
        });
        return error;
    }
    SUCCESS
}

pub fn launch_value_get(key: u64, output: u64) -> u64 {
    let process_id = match current_process() {
        Ok(process_id) => process_id,
        Err(error) => return error,
    };
    let value = match crate::task::with_process(process_id, |process| {
        process.launch_context().value(key)
    })
    .flatten()
    {
        Some(value) => value,
        None => return EBADF,
    };
    match crate::syscall::write_user_u64(output, value) {
        Ok(()) => SUCCESS,
        Err(error) => error,
    }
}

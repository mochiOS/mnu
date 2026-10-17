use alloc::sync::{Arc, Weak};
use alloc::vec;

mod snapshot;
pub use snapshot::table_read;
mod capture;
pub use capture::table_capture;
mod provider_reference;
pub use provider_reference::count as provider_object_reference_count;
mod memory_update;
pub use memory_update::create as provider_memory_update_create;
pub use memory_update::create_admission as provider_memory_admission_create;

use crate::task::{HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry, ProviderObject};

use super::{
    EACCES, EBADF, EINVAL, EIO, ENOSYS, ENOTSUP,
    SUCCESS,
};

pub(crate) fn flush_provider_releases() {
    let mut releases = crate::task::handle_table::take_provider_releases();
    while let Some(ticket) = releases.pop() {
        let release = *ticket.value();
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
            crate::task::handle_table::requeue_provider_release(ticket);
        }
    }
}

fn current_process() -> Result<crate::task::ProcessId, u64> {
    crate::syscall::security::current_process_id().ok_or(EINVAL)
}

/// Creates backing owned by the caller, not a view into another process.
/// Existing Handle duplication and IPC attachment paths enforce attenuation.
pub fn memory_object_create(length: u64, options: u64) -> u64 {
    use mnu_abi::status::Error;
    if options & !mnu_abi::MEMORY_OBJECT_RESIZABLE != 0 {
        return Error::InvalidArgument.into_raw();
    }
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process) => process,
        None => return Error::NotReady.into_raw(),
    };
    let result = crate::task::with_process_mut(process_id, |process| {
        let maximum_pages = process.resource_limits().max_mapped_pages as u64;
        let resizable = options & mnu_abi::MEMORY_OBJECT_RESIZABLE != 0;
        let backing = if resizable {
            crate::mem::shared_memory::SharedMemory::new_resizable(length, maximum_pages)
        } else {
            crate::mem::shared_memory::SharedMemory::new(length, maximum_pages)
        };
        let memory = Arc::try_new(backing?).map_err(|_| Error::ResourceUnavailable)?;
        let object = KernelObject::VmObject(
            Arc::try_new(crate::mem::vm_object::VmObject::shared_memory(memory))
                .map_err(|_| Error::ResourceUnavailable)?,
        );
        let mut rights = HandleRights::READ
            .union(HandleRights::WRITE)
            .union(HandleRights::MAP)
            .union(HandleRights::DUPLICATE)
            .union(HandleRights::TRANSFER);
        if resizable {
            rights = rights.union(HandleRights::CONTROL);
        }
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(object, rights))
            .map(|handle| handle.raw() as u64)
            .ok_or(Error::ResourceUnavailable)
    })
    .unwrap_or(Err(Error::NotReady));
    result.unwrap_or_else(Error::into_raw)
}

fn decode_handle(raw: u64) -> Result<ObjectHandle, u64> {
    let raw = u32::try_from(raw).map_err(|_| EBADF)?;
    ObjectHandle::from_raw(raw).ok_or(EBADF)
}

pub fn memory_object_length(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    match object_native(raw, HandleRights::MAP) {
        Ok(KernelObject::VmObject(object)) => object
            .memory_length()
            .unwrap_or_else(|| Error::InvalidArgument.into_raw()),
        Ok(_) => Error::InvalidArgument.into_raw(),
        Err(error) => error.into_raw(),
    }
}

pub fn memory_object_resize(raw: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    // Resolve and retain the resource before acquiring the mapping lock. Never
    // use a foreign PID/FD or hold a caller-table guard across global resize.
    match object_native(raw, HandleRights::CONTROL) {
        Ok(KernelObject::VmObject(object)) => object
            .resize_memory(length)
            .err()
            .map(Error::into_raw)
            .unwrap_or(SUCCESS),
        Ok(_) => Error::InvalidArgument.into_raw(),
        Err(error) => error.into_raw(),
    }
}

/// Retain only a caller-owned reference with the required authority. Invalid
/// Handle selectors are native InvalidArgument, not compatibility FD errors.
pub(crate) fn object_native(
    raw: u64,
    required_right: HandleRights,
) -> Result<KernelObject, mnu_abi::status::Error> {
    object_with_rights_native(raw, required_right).map(|(object, _)| object)
}

/// Return the retained object and its exact granted rights under the same
/// caller-table access, so later permission ceilings need no second lookup.
pub(crate) fn object_with_rights_native(
    raw: u64,
    required_right: HandleRights,
) -> Result<(KernelObject, HandleRights), mnu_abi::status::Error> {
    use mnu_abi::status::Error;
    let process_id = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
    let handle = u32::try_from(raw)
        .ok()
        .and_then(ObjectHandle::from_raw)
        .ok_or(Error::InvalidArgument)?;
    crate::task::with_process(process_id, |process| {
        let entry = process
            .object_handles()
            .get(handle)
            .ok_or(Error::InvalidArgument)?;
        if !entry.rights().contains(required_right) {
            return Err(Error::AccessDenied);
        }
        Ok((entry.object().clone(), entry.rights()))
    })
    .unwrap_or(Err(Error::NotReady))
}

pub(crate) fn object(raw: u64, required_right: HandleRights) -> Result<KernelObject, u64> {
    object_with_rights(raw, required_right).map(|(object, _)| object)
}

pub(crate) fn object_with_rights(
    raw: u64,
    required_right: HandleRights,
) -> Result<(KernelObject, HandleRights), u64> {
    let process_id = current_process()?;
    let handle = decode_handle(raw)?;
    crate::task::with_process(process_id, |process| {
        let entry = process.object_handles().get(handle).ok_or(EBADF)?;
        if !entry.rights().contains(required_right) {
            return Err(EACCES);
        }
        Ok((entry.object().clone(), entry.rights()))
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

pub fn write_bounded(raw: u64, buffer: u64, length: u64, byte_end: u64) -> u64 {
    match object(raw, HandleRights::WRITE) {
        Ok(KernelObject::Provider(provider)) => {
            provider_write_impl(&provider, buffer, length, Some(byte_end))
        }
        Ok(_) => ENOTSUP,
        Err(error) => error,
    }
}

pub fn stream_read(raw: u64, buffer: u64, length: u64, options: u64) -> u64 {
    if options & !mnu_abi::STREAM_READ_OPTIONS_ALL != 0 {
        return mnu_abi::status::Error::InvalidArgument.into_raw();
    }
    match object_native(raw, HandleRights::READ) {
        Ok(KernelObject::File(file)) => {
            crate::syscall::fs::read_stream_handle(&file, buffer, length, options)
        }
        Ok(_) => mnu_abi::status::Error::InvalidArgument.into_raw(),
        Err(error) => error.into_raw(),
    }
}

pub fn stream_write(raw: u64, buffer: u64, length: u64, options: u64) -> u64 {
    if options & !mnu_abi::STREAM_WRITE_OPTIONS_ALL != 0 {
        return mnu_abi::status::Error::InvalidArgument.into_raw();
    }
    match object_native(raw, HandleRights::WRITE) {
        Ok(KernelObject::File(file)) => {
            crate::syscall::fs::write_stream_handle(&file, buffer, length, options)
        }
        Ok(_) => mnu_abi::status::Error::InvalidArgument.into_raw(),
        Err(error) => error.into_raw(),
    }
}

pub fn seek(raw: u64, offset: u64, basis: u64) -> u64 {
    use mnu_abi::status::Error;

    let object = match object_native(raw, HandleRights::SEEK) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let basis = match basis {
        mnu_abi::HANDLE_SEEK_START => crate::syscall::fs::SeekBasis::Start,
        mnu_abi::HANDLE_SEEK_CURRENT => crate::syscall::fs::SeekBasis::Current,
        mnu_abi::HANDLE_SEEK_END => crate::syscall::fs::SeekBasis::End,
        _ => return Error::InvalidArgument.into_raw(),
    };
    match object {
        KernelObject::Provider(provider) => provider_seek(&provider, offset as i64, basis),
        _ => Error::InvalidArgument.into_raw(),
    }
}

pub fn read_at(raw: u64, buffer: u64, length: u64, offset: u64) -> u64 {
    positioned_io(raw, buffer, length, offset, false)
}

pub fn write_at(raw: u64, buffer: u64, length: u64, offset: u64) -> u64 {
    positioned_io(raw, buffer, length, offset, true)
}

fn positioned_io(raw: u64, buffer: u64, length: u64, offset: u64, write: bool) -> u64 {
    use mnu_abi::status::Error;

    let required = if write { HandleRights::WRITE } else { HandleRights::READ };
    let object = match object_native(raw, required) {
        Ok(object @ (KernelObject::Provider(_) | KernelObject::VmObject(_))) => object,
        Ok(object @ KernelObject::HandleSnapshot(_)) if !write => object,
        Ok(_) => return Error::InvalidArgument.into_raw(),
        Err(error) => return error.into_raw(),
    };
    if length > isize::MAX as u64 || offset.checked_add(length).is_none() {
        return Error::LimitExceeded.into_raw();
    }
    if length == 0 {
        return SUCCESS;
    }
    let identity = if let KernelObject::Provider(provider) = &object {
        match provider_cache_identity(provider) {
            Ok(identity) => identity,
            Err(error) => return error,
        }
    } else {
        None
    };
    let capacity = (length as usize).min(mnu_abi::provider::MAX_DATA_LEN);
    let mut data = alloc::vec::Vec::new();
    if data.try_reserve_exact(capacity).is_err() {
        return Error::ResourceUnavailable.into_raw();
    }
    data.resize(capacity, 0);
    let mut done = 0usize;
    while done < length as usize {
        let chunk = (length as usize - done).min(capacity);
        let address = match buffer.checked_add(done as u64) {
            Some(address) => address,
            None => {
                return if done == 0 {
                    Error::InvalidAddress.into_raw()
                } else {
                    done as u64
                };
            }
        };
        // A source/destination fault can load the same backing object. User
        // copies must never execute while its provider I/O guard is held.
        if write {
            if let Err(error) = crate::syscall::copy_from_user_native(address, &mut data[..chunk]) {
                return if done == 0 { error.into_raw() } else { done as u64 };
            }
        }
        let position = offset + done as u64;
        let result = match &object {
            KernelObject::Provider(provider) => {
                let _guard = match identity
                    .map(|identity| crate::mem::vm_object::lock_provider_io(provider, identity))
                    .transpose()
                    .map_err(mnu_abi::status::Error::into_raw)
                {
                    Ok(guard) => guard,
                    Err(error) => return if done == 0 { error } else { done as u64 },
                };
                if write {
                    provider_write_at(provider, position, &data[..chunk]).and_then(|count| {
                        if count > chunk {
                            return Err(Error::BackingFailure.into_raw());
                        }
                        if let Some(guard) = &_guard {
                            crate::mem::vm_object::update_provider_range(
                                guard, position, &data[..count],
                            );
                        }
                        Ok(count)
                    })
                } else {
                    provider_read_at(provider, position, &mut data[..chunk]).and_then(|count| {
                        if count > chunk {
                            return Err(Error::BackingFailure.into_raw());
                        }
                        if let Some(identity) = identity {
                            crate::mem::vm_object::overlay_provider_range(
                                provider, identity, position, &mut data[..count],
                            )?;
                        }
                        Ok(count)
                    })
                }
            }
            KernelObject::VmObject(object) if write => object.write_at(position, &data[..chunk]),
            KernelObject::VmObject(object) => object.read_at(position, &mut data[..chunk]),
            KernelObject::HandleSnapshot(snapshot) => {
                Ok(snapshot.read_at(position, &mut data[..chunk]))
            }
            _ => return Error::InvalidArgument.into_raw(),
        };
        let count = match result {
            Ok(count) if count <= chunk => count,
            Ok(_) => {
                return if done == 0 {
                    Error::BackingFailure.into_raw()
                } else {
                    done as u64
                };
            }
            Err(error) => return if done == 0 { error } else { done as u64 },
        };
        if !write {
            if let Err(error) = crate::syscall::copy_to_user_native(address, &data[..count]) {
                return if done == 0 { error.into_raw() } else { done as u64 };
            }
        }
        done += count;
        if count < chunk {
            break;
        }
    }
    done as u64
}

/// Controls a native update owner, or sends an opaque bounded control request
/// to a user-space-backed object.
/// The kernel enforces handle rights and memory safety but does not interpret
/// the provider-owned control code or payload.
pub fn control(
    raw: u64,
    control_code: u64,
    input: u64,
    input_length: u64,
    output: u64,
    output_length: u64,
) -> u64 {
    use mnu_abi::status::Error;

    let object = match object_native(raw, HandleRights::CONTROL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    if let KernelObject::MemoryUpdate(update) = &object {
        return memory_update::control(
            update, control_code, input, input_length, output, output_length,
        );
    }
    let KernelObject::Provider(provider) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let input_length = match usize::try_from(input_length) {
        Ok(length) if length <= mnu_abi::provider::MAX_DATA_LEN => length,
        _ => return Error::LimitExceeded.into_raw(),
    };
    let output_length = match usize::try_from(output_length) {
        Ok(length) if length <= mnu_abi::provider::MAX_DATA_LEN => length,
        _ => return Error::LimitExceeded.into_raw(),
    };
    let mut input_bytes = match crate::util::object_snapshot::zeroed_native(input_length) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    if input_length != 0 {
        if let Err(error) = crate::syscall::copy_from_user_native(input, &mut input_bytes) {
            return error.into_raw();
        }
    }
    let request = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_CONTROL,
        object_id: provider.object_id,
        argument: 0,
        basis: control_code,
        length: output_length as u32,
        data_length: input_length as u32,
    };
    let mut response_storage = match crate::util::object_snapshot::zeroed_native(
        mnu_abi::provider::RESPONSE_HEADER_LEN + output_length,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    let (response, data_length) =
        match provider_call(&provider, request, &input_bytes, &mut response_storage) {
            Ok(response) => response,
            Err(error) => return error,
        };
    if response.value != data_length as u64 || data_length > output_length {
        return Error::BackingFailure.into_raw();
    }
    if data_length != 0 {
        let data = &response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN
            ..mnu_abi::provider::RESPONSE_HEADER_LEN + data_length];
        if let Err(error) = crate::syscall::copy_to_user_native(output, data) {
            return error.into_raw();
        }
    }
    data_length as u64
}

pub fn options_get(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::CONTROL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    match object {
        KernelObject::File(file) => match crate::syscall::fs::file_handle_options(&file) {
            Ok(options) => options,
            Err(error) => error,
        },
        KernelObject::Provider(provider) => provider.io_options(),
        _ => Error::InvalidArgument.into_raw(),
    }
}

pub fn options_set(raw: u64, options: u64) -> u64 {
    use mnu_abi::status::Error;
    if options & !mnu_abi::HANDLE_OPTIONS_ALL != 0 {
        return Error::InvalidArgument.into_raw();
    }
    let object = match object_native(raw, HandleRights::CONTROL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    match object {
        KernelObject::File(file) => {
            match crate::syscall::fs::set_file_handle_options(&file, options) {
                Ok(()) => SUCCESS,
                Err(error) => error,
            }
        }
        KernelObject::Provider(provider) => {
            provider.set_io_options(options);
            SUCCESS
        }
        _ => Error::InvalidArgument.into_raw(),
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
    use mnu_abi::status::Error;

    if request_data.len() > mnu_abi::provider::MAX_DATA_LEN {
        return Err(Error::LimitExceeded.into_raw());
    }
    let request_capacity = mnu_abi::provider::REQUEST_HEADER_LEN
        .checked_add(request_data.len())
        .ok_or_else(|| Error::LimitExceeded.into_raw())?;
    let mut request = alloc::vec::Vec::new();
    request
        .try_reserve_exact(request_capacity)
        .map_err(|_| Error::ResourceUnavailable.into_raw())?;
    request.resize(request_capacity, 0);
    let request_len = request_header
        .encode(request_data, &mut request)
        .map_err(|_| Error::InvalidArgument.into_raw())?;
    let response_len = crate::syscall::ipc::call_provider_from_kernel(
        provider_endpoint(provider),
        &request[..request_len],
        response_storage,
    )?;
    let (response, data) = mnu_abi::provider::ResponseHeader::decode(
        response_storage.get(..response_len)
            .ok_or_else(|| Error::BackingFailure.into_raw())?,
    )
    .map_err(|_| Error::BackingFailure.into_raw())?;
    if response.opcode != request_header.opcode || response.object_id != provider.object_id {
        return Err(Error::BackingFailure.into_raw());
    }
    if response.status != 0 {
        return Err(response.status as u64);
    }
    Ok((response, data.len()))
}

/// Reads from a provider object without changing its sequential I/O offset.
/// This is the generic pager-facing operation used by native VM objects.
pub(crate) fn provider_read_at(
    provider: &ProviderObject,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, u64> {
    use mnu_abi::status::Error;

    if output.len() > mnu_abi::provider::MAX_DATA_LEN {
        return Err(Error::LimitExceeded.into_raw());
    }
    let request = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_READ_AT,
        object_id: provider.object_id,
        argument: 0,
        basis: offset,
        length: output.len() as u32,
        data_length: 0,
    };
    let capacity = mnu_abi::provider::RESPONSE_HEADER_LEN + output.len();
    let mut response_storage = alloc::vec::Vec::new();
    response_storage
        .try_reserve_exact(capacity)
        .map_err(|_| Error::ResourceUnavailable.into_raw())?;
    response_storage.resize(capacity, 0);
    let (response, data_len) = provider_call(provider, request, &[], &mut response_storage)?;
    if response.value as usize != data_len || data_len > output.len() {
        return Err(Error::BackingFailure.into_raw());
    }
    output[..data_len].copy_from_slice(
        &response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN
            ..mnu_abi::provider::RESPONSE_HEADER_LEN + data_len],
    );
    Ok(data_len)
}

/// Writes to a provider object without changing its sequential I/O offset.
pub(crate) fn provider_write_at(
    provider: &ProviderObject,
    offset: u64,
    input: &[u8],
) -> Result<usize, u64> {
    use mnu_abi::status::Error;

    if input.len() > mnu_abi::provider::MAX_DATA_LEN {
        return Err(Error::LimitExceeded.into_raw());
    }
    let request = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_WRITE_AT,
        object_id: provider.object_id,
        argument: 0,
        basis: offset,
        length: input.len() as u32,
        data_length: input.len() as u32,
    };
    let mut response_storage = [0u8; mnu_abi::provider::RESPONSE_HEADER_LEN];
    let (response, data_len) = provider_call(provider, request, input, &mut response_storage)?;
    let written = usize::try_from(response.value)
        .map_err(|_| Error::BackingFailure.into_raw())?;
    if data_len != 0 || written > input.len() {
        return Err(Error::BackingFailure.into_raw());
    }
    Ok(written)
}

pub(crate) fn provider_sync(provider: &ProviderObject) -> Result<(), u64> {
    use mnu_abi::status::Error;

    let request = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_SYNC,
        object_id: provider.object_id,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    };
    let mut response_storage = [0u8; mnu_abi::provider::RESPONSE_HEADER_LEN];
    let (response, data_len) = provider_call(provider, request, &[], &mut response_storage)?;
    if response.value != 0 || data_len != 0 {
        return Err(Error::BackingFailure.into_raw());
    }
    Ok(())
}

pub(crate) fn provider_memory_object(provider: &ProviderObject) -> Result<u64, u64> {
    use mnu_abi::status::Error;

    if provider.memory_identity_unavailable() {
        return Ok(0);
    }
    if let Some(cached) = provider.memory_identity() {
        return Ok(cached);
    }
    let request = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_MEMORY_OBJECT,
        object_id: provider.object_id,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    };
    let mut response_storage = [0u8; mnu_abi::provider::RESPONSE_HEADER_LEN];
    let (response, data_len) = provider_call(provider, request, &[], &mut response_storage)?;
    if data_len != 0 {
        return Err(Error::BackingFailure.into_raw());
    }
    if response.value == 0 {
        provider.set_memory_identity_unavailable();
    } else {
        provider.set_memory_identity(response.value);
    }
    Ok(response.value)
}

fn provider_cache_identity(provider: &ProviderObject) -> Result<Option<u64>, u64> {
    provider_memory_object(provider).map(|identity| (identity != 0).then_some(identity))
}

/// The caller retains its backing I/O guard through reading and cache overlay.
fn provider_read_chunk<'a>(
    provider: &ProviderObject,
    identity: Option<u64>,
    length: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8], u64> {
    use mnu_abi::provider as wire;
    let request = wire::RequestHeader {
        opcode: if identity.is_some() {
            wire::OP_READ_WITH_POSITION
        } else {
            wire::OP_READ
        },
        object_id: provider.object_id,
        argument: 0,
        basis: 0,
        length: length as u32,
        data_length: 0,
    };
    let (response, data_len) = provider_call(provider, request, &[], storage)?;
    let count = usize::try_from(response.value).map_err(|_| EIO)?;
    if count > length {
        return Err(EIO);
    }
    let data = &mut storage[wire::RESPONSE_HEADER_LEN..wire::RESPONSE_HEADER_LEN + data_len];
    if let Some(identity) = identity {
        if data.len() != wire::READ_POSITION_LEN + count {
            return Err(EIO);
        }
        let offset = u64::from_le_bytes(data[..wire::READ_POSITION_LEN].try_into().map_err(|_| EIO)?);
        let data = &mut data[wire::READ_POSITION_LEN..];
        crate::mem::vm_object::overlay_provider_range(provider, identity, offset, data)?;
        Ok(data)
    } else if count == data.len() {
        Ok(data)
    } else {
        Err(EIO)
    }
}

struct TemporaryMemoryHandle(u64);

impl Drop for TemporaryMemoryHandle {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

fn provider_read_shared(
    provider: &ProviderObject,
    identity: u64,
    buffer: u64,
    length: usize,
) -> u64 {
    use mnu_abi::provider as wire;
    let capacity = length.min(wire::MAX_SHARED_READ_LEN);
    let backing_length = (capacity as u64 + 4095) & !4095;
    let raw = memory_object_create(backing_length, 0);
    if (raw as i64) < 0 {
        return raw;
    }
    let _handle = TemporaryMemoryHandle(raw);
    let object = match object(raw, HandleRights::MAP) {
        Ok(KernelObject::VmObject(object)) => object,
        Ok(_) => return EIO,
        Err(error) => return error,
    };
    let handle = match decode_handle(raw) {
        Ok(handle) => handle,
        Err(error) => return error,
    };
    let requested = HandleRights::READ.union(HandleRights::WRITE).union(HandleRights::MAP);
    let mut data = vec![0u8; capacity];
    let mut total = 0usize;
    while total < length {
        let chunk = (length - total).min(capacity);
        let request = wire::RequestHeader {
            opcode: wire::OP_READ_SHARED,
            object_id: provider.object_id,
            argument: 0,
            basis: 0,
            length: chunk as u32,
            data_length: 0,
        };
        let mut encoded = [0u8; wire::REQUEST_HEADER_LEN];
        if request.encode(&[], &mut encoded).is_err() {
            return EINVAL;
        }
        let mut response = [0u8; wire::RESPONSE_HEADER_LEN + wire::READ_POSITION_LEN];
        let result = (|| -> Result<usize, u64> {
            let _io_guard = crate::mem::vm_object::lock_provider_io(provider, identity)
                .map_err(mnu_abi::status::Error::into_raw)?;
            let reply_length = crate::syscall::ipc::call_provider_with_handle_from_kernel(
                provider_endpoint(provider),
                &encoded,
                &mut response,
                handle,
                requested,
            )?;
            let (reply, position) = wire::ResponseHeader::decode(
                response.get(..reply_length).ok_or(EIO)?,
            )
            .map_err(|_| EIO)?;
            if reply.object_id != provider.object_id || reply.opcode != request.opcode {
                return Err(EIO);
            }
            if reply.status != 0 {
                return Err(reply.status as u64);
            }
            let count = usize::try_from(reply.value).map_err(|_| EIO)?;
            if count > chunk || position.len() != wire::READ_POSITION_LEN {
                return Err(EIO);
            }
            let start = u64::from_le_bytes(position.try_into().map_err(|_| EIO)?);
            if object.read_at(0, &mut data[..count])? != count {
                return Err(EIO);
            }
            crate::mem::vm_object::overlay_provider_range(
                provider, identity, start, &mut data[..count],
            )?;
            Ok(count)
        })();
        let count = match result {
            Ok(count) => count,
            Err(error) => return if total == 0 { error } else { total as u64 },
        };
        // User-buffer faults can read the same object: never retain its I/O
        // serialization guard across this copy.
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => return if total == 0 { EINVAL } else { total as u64 },
        };
        if let Err(error) = crate::syscall::copy_to_user(address, &data[..count]) {
            return if total == 0 { error } else { total as u64 };
        }
        total += count;
        if count < chunk {
            break;
        }
    }
    total as u64
}

fn provider_read(provider: &ProviderObject, buffer: u64, length: u64) -> u64 {
    let length = match usize::try_from(length) {
        Ok(length) => length,
        Err(_) => return EINVAL,
    };
    if length == 0 {
        return SUCCESS;
    }
    let identity = match provider_cache_identity(provider) {
        Ok(identity) => identity,
        Err(error) => return error,
    };
    if let Some(identity) = identity {
        if length > mnu_abi::provider::MAX_POSITIONED_READ_LEN {
            let result = provider_read_shared(provider, identity, buffer, length);
            // Providers can explicitly decline this optional transport without
            // losing support for ordinary object reads. No POSIX syscall path
            // is used, and other errors or partial reads are never retried.
            if result != ENOSYS && result != ENOTSUP {
                return result;
            }
        }
    }
    let maximum = if identity.is_some() {
        mnu_abi::provider::MAX_POSITIONED_READ_LEN
    } else {
        mnu_abi::provider::MAX_DATA_LEN
    };
    let mut total = 0usize;
    let mut response_storage =
        vec![0u8; mnu_abi::provider::RESPONSE_HEADER_LEN + mnu_abi::provider::MAX_DATA_LEN];
    while total < length {
        let chunk = (length - total).min(maximum);
        let data = {
            // User-buffer faults may load this same backing object. Release the
            // I/O guard before copying to user memory to avoid recursive locking.
            let _io_guard = match identity
                .map(|identity| crate::mem::vm_object::lock_provider_io(provider, identity))
                .transpose()
                .map_err(mnu_abi::status::Error::into_raw)
            {
                Ok(guard) => guard,
                Err(error) => return if total == 0 { error } else { total as u64 },
            };
            match provider_read_chunk(provider, identity, chunk, &mut response_storage) {
                Ok(data) => data,
                Err(error) => return if total == 0 { error } else { total as u64 },
            }
        };
        let data_len = data.len();
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => return if total == 0 { EINVAL } else { total as u64 },
        };
        if let Err(error) = crate::syscall::copy_to_user(address, data) {
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
    provider_write_impl(provider, buffer, length, None)
}

fn provider_write_impl(
    provider: &ProviderObject,
    buffer: u64,
    length: u64,
    byte_end: Option<u64>,
) -> u64 {
    let length = match usize::try_from(length) {
        Ok(length) => length,
        Err(_) => return EINVAL,
    };
    if length == 0 {
        // A Provider owns the meaning of an empty operation too. Do not
        // fabricate success or inspect the unused user buffer on its behalf.
        let request = mnu_abi::provider::RequestHeader {
            opcode: if byte_end.is_some() {
                mnu_abi::provider::OP_WRITE_BOUNDED
            } else {
                mnu_abi::provider::OP_WRITE
            },
            object_id: provider.object_id,
            argument: 0,
            basis: byte_end.unwrap_or(0),
            length: 0,
            data_length: 0,
        };
        let mut response = [0; mnu_abi::provider::RESPONSE_HEADER_LEN + 8];
        return match provider_call(provider, request, &[], &mut response) {
            Ok((header, data_len @ (0 | 8)))
                if header.value == 0 && (byte_end.is_none() || data_len == 8) => SUCCESS,
            Ok(_) => EIO,
            Err(error) => error,
        };
    }
    let identity = match provider_cache_identity(provider) {
        Ok(identity) => identity,
        Err(error) => return error,
    };
    let mut total = 0usize;
    let mut data = vec![0u8; mnu_abi::provider::MAX_DATA_LEN];
    let mut response_storage = vec![0u8; mnu_abi::provider::RESPONSE_HEADER_LEN + 8];
    while total < length {
        let chunk = (length - total).min(data.len());
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => return if total == 0 { EINVAL } else { total as u64 },
        };
        if let Err(error) = crate::syscall::copy_from_user(address, &mut data[..chunk]) {
            return if total == 0 { error } else { total as u64 };
        }
        // Faulting the source buffer may load this same backing object. Only
        // serialize the provider operation and resident-page update afterward.
        let _io_guard = match identity
            .map(|identity| crate::mem::vm_object::lock_provider_io(provider, identity))
            .transpose()
            .map_err(mnu_abi::status::Error::into_raw)
        {
            Ok(guard) => guard,
            Err(error) => return if total == 0 { error } else { total as u64 },
        };
        let request = mnu_abi::provider::RequestHeader {
            opcode: if byte_end.is_some() {
                mnu_abi::provider::OP_WRITE_BOUNDED
            } else {
                mnu_abi::provider::OP_WRITE
            },
            object_id: provider.object_id,
            argument: 0,
            basis: byte_end.unwrap_or(0),
            length: chunk as u32,
            data_length: chunk as u32,
        };
        let (response, data_len) =
            match provider_call(provider, request, &data[..chunk], &mut response_storage) {
                Ok(response) => response,
                Err(error) => return if total == 0 { error } else { total as u64 },
            };
        let written = match usize::try_from(response.value) {
            Ok(written)
                if (data_len == 8 || (byte_end.is_none() && data_len == 0)) && written <= chunk =>
            {
                written
            }
            _ => return if total == 0 { EIO } else { total as u64 },
        };
        let mut reached_end = false;
        if written != 0 && data_len == 8 {
            let start = u64::from_le_bytes(
                response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN..]
                    .try_into()
                    .unwrap(),
            );
            if let Some(end) = byte_end {
                let Some(after) = start.checked_add(written as u64).filter(|after| *after <= end)
                else {
                    return if total == 0 { EIO } else { total as u64 };
                };
                reached_end = after == end;
            }
            if let Some(guard) = &_io_guard {
                crate::mem::vm_object::update_provider_range(
                    guard,
                    start,
                    &data[..written],
                );
            }
        }
        total += written;
        if written < chunk || reached_end {
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
        Ok((response, 0)) if response.value <= i64::MAX as u64 => Ok(response.value),
        Ok((_, 0)) => Err(mnu_abi::status::Error::LimitExceeded.into_raw()),
        Ok(_) => Err(mnu_abi::status::Error::BackingFailure.into_raw()),
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
/// Local failures use native statuses; lower I/O failures are propagated intact
/// while the provider/pager error boundary is migrated separately.
pub(crate) fn read_all(raw: u64, maximum_length: usize) -> Result<alloc::vec::Vec<u8>, u64> {
    use mnu_abi::status::Error;

    let readable = object_native(raw, HandleRights::READ).map_err(Error::into_raw)?;
    if let KernelObject::VmObject(memory) = readable {
        let length = memory
            .memory_length()
            .ok_or(Error::InvalidArgument.into_raw())?;
        return crate::util::object_snapshot::read(length, maximum_length, |bytes| {
            memory.read_at(0, bytes)
        });
    }
    // Provider snapshots retain the existing seek/cursor contract. RAM above
    // has explicit-position reads, so it neither needs nor receives SEEK.
    let object = object_native(raw, HandleRights::READ.union(HandleRights::SEEK))
        .map_err(Error::into_raw)?;
    let KernelObject::Provider(provider) = object else {
        return Err(Error::InvalidArgument.into_raw());
    };
    let identity = provider_cache_identity(&provider)?;
    let _io_guard = identity
        .map(|identity| crate::mem::vm_object::lock_provider_io(&provider, identity))
        .transpose()
        .map_err(mnu_abi::status::Error::into_raw)?;
    let maximum = if identity.is_some() {
        mnu_abi::provider::MAX_POSITIONED_READ_LEN
    } else {
        mnu_abi::provider::MAX_DATA_LEN
    };
    let length = provider_seek_result(&provider, 0, crate::syscall::fs::SeekBasis::End)?;
    let length = usize::try_from(length).map_err(|_| Error::LimitExceeded.into_raw())?;
    if length > maximum_length {
        return Err(Error::LimitExceeded.into_raw());
    }
    provider_seek_result(&provider, 0, crate::syscall::fs::SeekBasis::Start)?;
    let mut output = crate::util::object_snapshot::zeroed_native(length).map_err(Error::into_raw)?;
    let mut offset = 0usize;
    let mut response_storage = crate::util::object_snapshot::zeroed_native(
        mnu_abi::provider::RESPONSE_HEADER_LEN + mnu_abi::provider::MAX_DATA_LEN,
    )
    .map_err(Error::into_raw)?;
    while offset < output.len() {
        let chunk = (output.len() - offset).min(maximum);
        let data = provider_read_chunk(&provider, identity, chunk, &mut response_storage)?;
        let data_len = data.len();
        if data_len == 0 {
            return Err(Error::BackingFailure.into_raw());
        }
        output[offset..offset + data_len].copy_from_slice(data);
        offset += data_len;
    }
    Ok(output)
}

pub fn provider_object_create(endpoint: u64, object_id: u64, requested_rights: u64) -> u64 {
    use mnu_abi::status::Error;
    // Object IDs are returned directly by ProviderObjectIdentify, so keep the
    // syscall's negative range unambiguous.
    if object_id > i64::MAX as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) => rights,
        None => return Error::InvalidArgument.into_raw(),
    };
    let (endpoint_thread_id, endpoint_slot, endpoint_generation) =
        match crate::syscall::ipc::resolve_provider_endpoint_native(endpoint) {
            Ok(endpoint) => endpoint,
            Err(error) => return error.into_raw(),
        };
    let provider = match ProviderObject::new(
        endpoint_thread_id,
        endpoint_slot,
        endpoint_generation,
        object_id,
    ) {
        Ok(provider) => match Arc::try_new(provider) {
            Ok(provider) => provider,
            Err(_) => return Error::ResourceUnavailable.into_raw(),
        },
        Err(error) => return error.into_raw(),
    };
    if !crate::task::handle_table::register_provider_object(&provider) {
        return Error::AlreadyExists.into_raw();
    }
    let object = KernelObject::Provider(provider);
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(object, rights))
            .map(|handle| handle.raw() as u64)
            .unwrap_or(Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or(Error::NotReady.into_raw())
}

/// Returns the opaque identifier of a provider object only to the exact
/// endpoint thread that created it.
pub fn provider_object_identify(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let provider = match object_native(raw, HandleRights::empty()) {
        Ok(KernelObject::Provider(provider)) => provider,
        Ok(_) => return Error::InvalidArgument.into_raw(),
        Err(error) => return error.into_raw(),
    };
    let current = match crate::task::current_thread_id()
        .and_then(|thread| crate::syscall::ipc::endpoint_for_thread(thread.as_u64()))
    {
        Some(endpoint) => endpoint,
        None => return Error::NotReady.into_raw(),
    };
    if provider.endpoint_thread_id != current.thread_id
        || provider.endpoint_slot != current.slot
        || provider.endpoint_generation != current.generation
    {
        return Error::AccessDenied.into_raw();
    }
    provider.object_id
}

/// Updates native readiness signals for an object owned by the caller's
/// provider endpoint. The object identifier is meaningful only inside that
/// endpoint and cannot address objects owned by another provider.
pub fn provider_object_signal(object_id: u64, set: u64, clear: u64) -> u64 {
    use mnu_abi::status::Error;
    let supported = mnu_abi::HANDLE_SIGNAL_READABLE
        | mnu_abi::HANDLE_SIGNAL_WRITABLE
        | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
        | mnu_abi::HANDLE_SIGNAL_IDLE;
    if object_id > i64::MAX as u64
        || set & !supported != 0
        || clear & !supported != 0
        || set & clear != 0
    {
        return Error::InvalidArgument.into_raw();
    }
    let current = match crate::task::current_thread_id()
        .and_then(|thread| crate::syscall::ipc::endpoint_for_thread(thread.as_u64()))
    {
        Some(endpoint) => endpoint,
        None => return Error::NotReady.into_raw(),
    };
    let Some(provider) = crate::task::handle_table::provider_object(
        current.thread_id,
        current.slot,
        current.generation,
        object_id,
    ) else {
        return Error::InvalidArgument.into_raw();
    };
    provider.update_signals(set, clear);
    SUCCESS
}

pub fn close(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let handle = match u32::try_from(raw).ok().and_then(ObjectHandle::from_raw) {
        Some(handle) => handle,
        None => return Error::InvalidArgument.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        if !process.object_handles_mut().close(handle) {
            return Error::InvalidArgument.into_raw();
        }
        process.launch_context_mut().remove_handle(handle);
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn duplicate(raw: u64, requested_rights: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let handle = match u32::try_from(raw).ok().and_then(ObjectHandle::from_raw) {
        Some(handle) => handle,
        None => return Error::InvalidArgument.into_raw(),
    };
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) => rights,
        None => return Error::InvalidArgument.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        let Some(source) = process.object_handles().get(handle) else {
            return Error::InvalidArgument.into_raw();
        };
        if !source.rights().contains(HandleRights::DUPLICATE) || !source.rights().contains(rights) {
            return Error::AccessDenied.into_raw();
        }
        match process
            .object_handles_mut()
            .duplicate_restricted(handle, rights)
        {
            Some(duplicate) => duplicate.raw() as u64,
            None => Error::ResourceUnavailable.into_raw(),
        }
    })
    .unwrap_or(Error::NotReady.into_raw())
}

/// Compares two process-local handles without disclosing a globally reusable
/// object identifier. Possession of both valid handles is sufficient.
pub fn same_object(left_raw: u64, right_raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let decode = |raw| u32::try_from(raw).ok().and_then(ObjectHandle::from_raw);
    let (Some(left), Some(right)) = (decode(left_raw), decode(right_raw)) else {
        return Error::InvalidArgument.into_raw();
    };
    crate::task::with_process(process_id, |process| {
        let Some(left) = process.object_handles().get(left) else {
            return Error::InvalidArgument.into_raw();
        };
        let Some(right) = process.object_handles().get(right) else {
            return Error::InvalidArgument.into_raw();
        };
        u64::from(left.object().is_same_object(right.object()))
    })
    .unwrap_or(Error::NotReady.into_raw())
}

const PROCESS_HANDLE_RIGHTS: HandleRights = HandleRights::WAIT
    .union(HandleRights::DUPLICATE)
    .union(HandleRights::TRANSFER);

const PROCESS_ADMIN_HANDLE_RIGHTS: HandleRights = PROCESS_HANDLE_RIGHTS.union(HandleRights::SIGNAL);

/// Retain an object created by this caller before its first thread is published.
/// This is not a lookup API: only the authorized creation path calls it.
pub(super) fn retain_created_process(
    target: &crate::task::Process,
) -> Result<u64, mnu_abi::status::Error> {
    use mnu_abi::status::Error;
    let owner = crate::syscall::security::current_process_id().ok_or(Error::NotReady)?;
    let object = target.process_object();
    crate::task::with_process_mut(owner, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Process(object),
                PROCESS_ADMIN_HANDLE_RIGHTS,
            ))
            .map(|handle| handle.raw() as u64)
            .ok_or(Error::ResourceUnavailable)
    })
    .ok_or(Error::NotReady)?
}

fn insert_process_handle(target: crate::task::ProcessId, rights: HandleRights) -> u64 {
    use mnu_abi::status::Error;
    let Some(target_object) = crate::task::with_process(target, |process| process.process_object())
    else {
        return Error::NotFound.into_raw();
    };
    let Some(process_id) = crate::syscall::security::current_process_id() else {
        return Error::NotReady.into_raw();
    };
    crate::task::with_process_mut(process_id, |process| {
        process
            .object_handles_mut()
            .insert(ObjectHandleEntry::new(
                KernelObject::Process(target_object),
                rights,
            ))
            .map(|handle| handle.raw() as u64)
            .unwrap_or_else(|| Error::ResourceUnavailable.into_raw())
    })
    .unwrap_or_else(|| Error::NotReady.into_raw())
}

/// Creates a process handle for the process owning an authenticated IPC
/// endpoint. No caller-supplied process identifier is accepted.
pub fn process_open(endpoint: u64, requested_rights: u64) -> u64 {
    use mnu_abi::status::Error;
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return Error::AccessDenied.into_raw();
    }
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) if PROCESS_ADMIN_HANDLE_RIGHTS.contains(rights) => rights,
        _ => return Error::InvalidArgument.into_raw(),
    };
    if rights.contains(HandleRights::SIGNAL)
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::ProcessKill,
        ])
    {
        return Error::AccessDenied.into_raw();
    }
    let Some(thread_id) = crate::syscall::ipc::resolve_endpoint_handle(endpoint) else {
        return Error::InvalidArgument.into_raw();
    };
    let Some(target) = crate::task::thread_to_process_id(thread_id) else {
        return Error::NotFound.into_raw();
    };
    insert_process_handle(target, rights)
}

/// Creates a native handle for a process identifier. Process identifiers are
/// generic kernel identities; requested control rights are capability-gated.
pub fn process_open_by_id(process_id: u64, requested_rights: u64) -> u64 {
    use mnu_abi::status::Error;
    if process_id == 0 {
        return Error::InvalidArgument.into_raw();
    }
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return Error::AccessDenied.into_raw();
    }
    let rights = match HandleRights::from_bits(requested_rights) {
        Some(rights) if PROCESS_ADMIN_HANDLE_RIGHTS.contains(rights) => rights,
        _ => return Error::InvalidArgument.into_raw(),
    };
    if rights.contains(HandleRights::SIGNAL)
        && !crate::syscall::security::caller_has_any_capability(&[
            crate::capability::Capability::ProcessKill,
        ])
    {
        return Error::AccessDenied.into_raw();
    }
    insert_process_handle(crate::task::ProcessId::from_u64(process_id), rights)
}

fn process_status_for(raw: u64) -> Result<mnu_abi::ProcessStatus, u64> {
    use mnu_abi::status::Error;
    let object = object_native(raw, HandleRights::WAIT).map_err(Error::into_raw)?;
    let KernelObject::Process(process) = object else {
        return Err(Error::InvalidArgument.into_raw());
    };
    Ok(process_status_of(&process))
}

fn process_status_of(process: &crate::task::process::ProcessObject) -> mnu_abi::ProcessStatus {
    let exited = process.is_exited();
    mnu_abi::ProcessStatus {
        process_id: process.id().as_u64(),
        state: if exited {
            mnu_abi::PROCESS_STATE_EXITED
        } else {
            mnu_abi::PROCESS_STATE_RUNNING
        },
        reserved: 0,
        exit_code: process.exit_code(),
    }
}

fn write_process_status(output: u64, status: mnu_abi::ProcessStatus) -> u64 {
    use mnu_abi::status::Error;
    if output == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&status as *const mnu_abi::ProcessStatus).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ProcessStatus>(),
        )
    };
    crate::syscall::copy_to_user_native(output, bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(Error::into_raw)
}

pub fn process_status(raw: u64, output: u64) -> u64 {
    match process_status_for(raw) {
        Ok(status) => write_process_status(output, status),
        Err(error) => error,
    }
}

fn process_execution_usage_for(raw: u64) -> Result<mnu_abi::ProcessExecutionUsage, u64> {
    use mnu_abi::status::Error;
    let process = if raw == 0 {
        let caller = crate::syscall::security::current_process_id()
            .ok_or_else(|| Error::NotReady.into_raw())?;
        crate::task::with_process(caller, |process| process.process_object())
            .ok_or_else(|| Error::NotReady.into_raw())?
    } else {
        let KernelObject::Process(process) =
            object_native(raw, HandleRights::WAIT).map_err(Error::into_raw)?
        else {
            return Err(Error::InvalidArgument.into_raw());
        };
        process
    };
    let ticks_per_second = crate::interrupt::timer::ticks_per_second();
    if ticks_per_second == 0 {
        return Err(Error::NotReady.into_raw());
    }
    let (user_ticks, kernel_ticks) = crate::task::thread::process_execution_ticks(&process);
    Ok(mnu_abi::ProcessExecutionUsage {
        user_ticks,
        kernel_ticks,
        ticks_per_second,
        reserved: 0,
    })
}

pub fn process_execution_read(raw: u64, output: u64, length: u64) -> u64 {
    use mnu_abi::status::Error;
    if length != core::mem::size_of::<mnu_abi::ProcessExecutionUsage>() as u64 {
        return Error::InvalidArgument.into_raw();
    }
    let usage = match process_execution_usage_for(raw) {
        Ok(usage) => usage,
        Err(error) => return error,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&usage as *const mnu_abi::ProcessExecutionUsage).cast::<u8>(),
            core::mem::size_of::<mnu_abi::ProcessExecutionUsage>(),
        )
    };
    crate::syscall::copy_to_user_native(output, bytes)
        .map(|_| SUCCESS)
        .unwrap_or_else(Error::into_raw)
}

/// Waits until the process exits. `deadline_nanoseconds` is an absolute
/// monotonic-clock value; zero polls and `u64::MAX` waits indefinitely.
pub fn process_wait(raw: u64, deadline_nanoseconds: u64, output: u64) -> u64 {
    use mnu_abi::status::Error;
    // Retain the target once: concurrent close/reuse of the caller's selector
    // must not redirect a pending wait to a different lifecycle object.
    let process = match object_native(raw, HandleRights::WAIT) {
        Ok(KernelObject::Process(process)) => process,
        Ok(_) => return Error::InvalidArgument.into_raw(),
        Err(error) => return error.into_raw(),
    };
    let process_id = process.id();
    let current = match crate::task::current_thread_id() {
        Some(thread) => thread,
        None => return Error::NotReady.into_raw(),
    };
    struct Registration {
        thread: crate::task::ThreadId,
        process: crate::task::ProcessId,
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            crate::task::remove_process_exit_waiter(self.thread, self.process);
            crate::syscall::time::disarm_thread_deadline(self.thread);
        }
    }
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
        let registration = Registration {
            thread: current,
            process: process_id,
        };
        let status = process_status_of(&process);
        if status.state == mnu_abi::PROCESS_STATE_EXITED {
            drop(registration);
            return write_process_status(output, status);
        }
        if deadline_nanoseconds == mnu_abi::PROCESS_WAIT_POLL
            || (deadline_nanoseconds != mnu_abi::PROCESS_WAIT_INFINITE
                && crate::syscall::time::monotonic_nanoseconds() >= deadline_nanoseconds)
        {
            return Error::NotReady.into_raw();
        }
        if super::upcall::current_has_deliverable_upcall() {
            return Error::NotReady.into_raw();
        }
        if !crate::task::register_process_exit_waiter(current, process_id) {
            return Error::ResourceUnavailable.into_raw();
        }

        // Recheck after registration so an exit racing with registration
        // cannot be missed.
        let status = process_status_of(&process);
        if status.state == mnu_abi::PROCESS_STATE_EXITED {
            drop(registration);
            return write_process_status(output, status);
        }

        if deadline_nanoseconds != mnu_abi::PROCESS_WAIT_INFINITE
            && !crate::syscall::time::arm_thread_deadline(current, deadline_tick)
        {
            return Error::ResourceUnavailable.into_raw();
        }
        let _ = crate::task::sleep_thread_unless_woken(current);
        crate::task::yield_now();
    }
}

#[derive(Clone)]
enum WaitTarget {
    Process(crate::task::ProcessId),
    IpcEndpoint(crate::syscall::ipc::IpcEndpoint),
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

fn wait_item_signal(
    item: &mut mnu_abi::HandleWaitItem,
    source: &WaitSource,
) -> Result<(WaitTarget, bool), u64> {
    use mnu_abi::status::Error;
    if item.interests == 0 {
        return Err(Error::InvalidArgument.into_raw());
    }
    let object = object_native(u64::from(item.handle), HandleRights::WAIT)
        .map_err(Error::into_raw)?;
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
        KernelObject::IpcEndpoint {
            thread_id,
            slot,
            generation,
        } => {
            if item.interests & !mnu_abi::HANDLE_SIGNAL_READABLE != 0 {
                return Err(Error::InvalidArgument.into_raw());
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
        KernelObject::MemoryAdmission(admission) => {
            let supported = mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            if item.interests & !supported != 0 {
                return Err(Error::InvalidArgument.into_raw());
            }
            if !crate::syscall::ipc::endpoint_is_valid(memory_update::admission_endpoint(&admission)) {
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
            if !crate::syscall::ipc::endpoint_is_valid(provider_endpoint(&provider)) {
                return Err(Error::NotFound.into_raw());
            }
            item.observed = provider.signals() & item.interests;
            Ok((WaitTarget::Provider(provider), item.observed != 0))
        }
        _ => Err(Error::InvalidArgument.into_raw()),
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

fn remove_provider_waiters(waiter: crate::task::ThreadId, providers: &[Arc<ProviderObject>]) {
    for provider in providers {
        provider.remove_waiter(waiter);
    }
}

/// Own every explicit subscription until the object wait leaves kernel mode.
/// Cleanup is idempotent, including after partial deadline admission.
struct ObjectWaitRegistrations {
    thread: crate::task::ThreadId,
    endpoints: alloc::vec::Vec<crate::syscall::ipc::IpcEndpoint>,
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

fn copy_wait_items_to_user(items_ptr: u64, items: &[mnu_abi::HandleWaitItem]) -> Result<(), u64> {
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
        if let Err(error) = super::address_wait::read_guard_value(address) {
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
    let mut registrations = ObjectWaitRegistrations {
        thread: current,
        endpoints: alloc::vec::Vec::new(),
        streams: alloc::vec::Vec::new(),
        providers: alloc::vec::Vec::new(),
    };
    let registered_endpoints = &mut registrations.endpoints;
    let registered_streams = &mut registrations.streams;
    let registered_providers = &mut registrations.providers;
    let mut endpoint_lifetimes = alloc::vec::Vec::new();
    let mut admission_waiters = alloc::vec::Vec::<memory_update::AdmissionWaiter>::new();
    let mut sources = alloc::vec::Vec::new();
    let mut targets = alloc::vec::Vec::new();
    // Each item contributes at most one target/subscription of each kind.
    // Reserve before admitting any waiter; no push in the wait loop allocates.
    if registered_endpoints.try_reserve_exact(count).is_err()
        || registered_streams.try_reserve_exact(count).is_err()
        || registered_providers.try_reserve_exact(count).is_err()
        || endpoint_lifetimes.try_reserve_exact(count).is_err()
        || admission_waiters.try_reserve_exact(count).is_err()
        || sources.try_reserve_exact(count).is_err()
        || targets.try_reserve_exact(count).is_err()
    {
        return mnu_abi::status::Error::ResourceUnavailable.into_raw();
    }
    for item in &items {
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
        crate::task::remove_process_exit_waiters(current);
        remove_endpoint_waiters(current, &registered_endpoints);
        remove_stream_waiters(current, &registered_streams);
        remove_provider_waiters(current, &registered_providers);
        registered_endpoints.clear();
        registered_streams.clear();
        registered_providers.clear();
        endpoint_lifetimes.clear();
        admission_waiters.clear();
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
        let _guard_waiter = match guard {
            Some(guard) => match super::address_wait::register_guard(
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
            },
            None => None,
        };
        if let Some(guard) = guard {
            match super::address_wait::read_guard_value(guard.address) {
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
        if super::upcall::current_has_deliverable_upcall() {
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
                WaitTarget::MemoryAdmission(admission) => {
                    let registered = (|| {
                        let endpoint = memory_update::admission_endpoint(&admission);
                        let observation =
                            crate::syscall::ipc::lifetime::observe(endpoint, current)?;
                        let waiter = memory_update::AdmissionWaiter::register(admission, current)?;
                        admission_waiters.push(waiter);
                        endpoint_lifetimes.push(observation);
                        Ok::<(), u64>(())
                    })();
                    if let Err(error) = registered {
                        crate::task::remove_process_exit_waiters(current);
                        remove_endpoint_waiters(current, &registered_endpoints);
                        remove_stream_waiters(current, &registered_streams);
                        remove_provider_waiters(current, &registered_providers);
                        return error;
                    }
                }
                WaitTarget::Process(process_id) => {
                    if !crate::task::register_process_exit_waiter(current, process_id) {
                        crate::task::remove_process_exit_waiters(current);
                        remove_endpoint_waiters(current, &registered_endpoints);
                        remove_stream_waiters(current, &registered_streams);
                        remove_provider_waiters(current, &registered_providers);
                        return Error::ResourceUnavailable.into_raw();
                    }
                }
                WaitTarget::IpcEndpoint(endpoint) => {
                    if let Err(error) =
                        crate::syscall::ipc::register_endpoint_waiter(endpoint, current)
                    {
                        crate::task::remove_process_exit_waiters(current);
                        remove_endpoint_waiters(current, &registered_endpoints);
                        remove_stream_waiters(current, &registered_streams);
                        remove_provider_waiters(current, &registered_providers);
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
                            remove_provider_waiters(current, &registered_providers);
                            return error;
                        }
                    }
                }
                WaitTarget::Provider(provider) => {
                    match crate::syscall::ipc::lifetime::observe(provider_endpoint(&provider), current) {
                        Ok(observation) => endpoint_lifetimes.push(observation),
                        Err(error) => {
                            crate::task::remove_process_exit_waiters(current);
                            remove_endpoint_waiters(current, &registered_endpoints);
                            remove_stream_waiters(current, &registered_streams);
                            remove_provider_waiters(current, &registered_providers);
                            return error;
                        }
                    }
                    if !provider.register_waiter(current) {
                        crate::task::remove_process_exit_waiters(current);
                        remove_endpoint_waiters(current, &registered_endpoints);
                        remove_stream_waiters(current, &registered_streams);
                        remove_provider_waiters(current, &registered_providers);
                        return Error::ResourceUnavailable.into_raw();
                    }
                    registered_providers.push(provider);
                }
            }
        }
        if deadline_nanoseconds != mnu_abi::HANDLE_WAIT_INFINITE
            && !crate::syscall::time::arm_thread_deadline(current, deadline_tick)
        {
            crate::task::remove_process_exit_waiters(current);
            remove_endpoint_waiters(current, &registered_endpoints);
            remove_stream_waiters(current, &registered_streams);
            remove_provider_waiters(current, &registered_providers);
            return Error::ResourceUnavailable.into_raw();
        }

        // Recheck after waiter registration so exits racing with registration
        // cannot be missed. A pending wakeup prevents sleeping in that case.
        let mut became_ready = false;
        for (index, item) in items.iter_mut().enumerate() {
            match wait_item_signal(item, &sources[index]) {
                Ok((_, is_ready)) => became_ready |= is_ready,
                Err(error) => {
                    crate::task::remove_process_exit_waiters(current);
                    remove_endpoint_waiters(current, &registered_endpoints);
                    remove_stream_waiters(current, &registered_streams);
                    remove_provider_waiters(current, &registered_providers);
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
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Process(process) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let process_id = process.id();
    if process.is_exited() || crate::task::with_process(process_id, |_| ()).is_none() {
        return Error::NotFound.into_raw();
    }
    if crate::task::resume_process_threads(process_id).is_none() {
        return Error::NotFound.into_raw();
    }
    SUCCESS
}

/// Suspends every thread belonging to the process referenced by `raw`.
/// This is a policy-free lifecycle operation; callers assign their own
/// meaning to the scheduling state.
pub fn process_suspend(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Process(process) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let process_id = process.id();
    if process.is_exited() || crate::task::with_process(process_id, |_| ()).is_none() {
        return Error::NotFound.into_raw();
    }
    if crate::task::suspend_process_threads(process_id) == 0 {
        return Error::NotReady.into_raw();
    }
    SUCCESS
}

pub fn process_terminate(raw: u64, exit_code: u64) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::SIGNAL) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Process(process) = object else {
        return Error::InvalidArgument.into_raw();
    };
    let process_id = process.id();
    if process.is_exited() || crate::task::with_process(process_id, |_| ()).is_none() {
        return Error::NotFound.into_raw();
    }
    if crate::syscall::security::current_process_id() == Some(process_id) {
        crate::task::scheduler::exit_current_process(exit_code);
    }
    if !process.begin_termination() {
        return if process.is_exited() {
            Error::NotFound.into_raw()
        } else {
            Error::NotReady.into_raw()
        };
    }
    crate::task::scheduler::retire_process_threads(process_id, None);
    let cleanup = crate::task::release_process_borrowed_mappings(process_id);
    if !crate::task::mark_process_exited(process_id, exit_code) {
        return Error::NotFound.into_raw();
    }
    // Terminal publication succeeded. Reporting cleanup failure as termination
    // failure would make callers lose the winning termination cause. Deferred
    // process reclaim retains the address space and retries mapping revocation.
    if let Err(error) = cleanup {
        crate::warn!(
            "Borrowed mapping cleanup deferred for {:?}: {:#x}",
            process_id,
            error
        );
    }
    SUCCESS
}

pub fn launch_get(key: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process(process_id, |process| {
        let Some(handle) = process.launch_context().get(key) else {
            return Error::NotFound.into_raw();
        };
        if process.object_handles().get(handle).is_none() {
            return Error::InvalidArgument.into_raw();
        }
        handle.raw() as u64
    })
    .unwrap_or(Error::NotReady.into_raw())
}

/// Associates one of the caller's existing object handles with an opaque
/// process-context key, replacing the previous association for that key. The
/// kernel assigns no meaning to either the key or the object.
pub fn context_handle_set(key: u64, raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let handle = match u32::try_from(raw).ok().and_then(ObjectHandle::from_raw) {
        Some(handle) => handle,
        None => return Error::InvalidArgument.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        if process.object_handles().get(handle).is_none() {
            return Error::InvalidArgument.into_raw();
        }
        if !process.launch_context_mut().set(key, handle) {
            return Error::ResourceUnavailable.into_raw();
        }
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn context_handle_remove(key: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        process.launch_context_mut().take(key);
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn context_value_set(key: u64, value: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        if !process.launch_context_mut().set_value(key, value) {
            return Error::ResourceUnavailable.into_raw();
        }
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn context_value_remove(key: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    crate::task::with_process_mut(process_id, |process| {
        process.launch_context_mut().remove_value(key);
        SUCCESS
    })
    .unwrap_or(Error::NotReady.into_raw())
}

pub fn rights_get(raw: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let handle = match u32::try_from(raw).ok().and_then(ObjectHandle::from_raw) {
        Some(handle) => handle,
        None => return Error::InvalidArgument.into_raw(),
    };
    crate::task::with_process(process_id, |process| {
        process
            .object_handles()
            .get(handle)
            .map(|entry| entry.rights().bits())
            .unwrap_or(Error::InvalidArgument.into_raw())
    })
    .unwrap_or(Error::NotReady.into_raw())
}

/// Creates a native unidirectional byte stream as two object handles.
/// Descriptor numbering and POSIX descriptor flags are intentionally left to
/// user space.
pub fn stream_pair_create(output: u64) -> u64 {
    use mnu_abi::status::Error;

    if output == 0 {
        return Error::InvalidAddress.into_raw();
    }
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let Some(stream_id) = crate::syscall::fs::alloc_stream_state() else {
        return Error::ResourceUnavailable.into_raw();
    };
    let (read, write) = match crate::task::FileHandle::try_stream_pair(stream_id) {
        Ok(pair) => pair,
        Err(error) => return error.into_raw(),
    };
    let read = match Arc::try_new(read) {
        Ok(read) => KernelObject::File(read),
        Err(_) => return Error::ResourceUnavailable.into_raw(),
    };
    let write = match Arc::try_new(write) {
        Ok(write) => KernelObject::File(write),
        Err(_) => return Error::ResourceUnavailable.into_raw(),
    };
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
    });
    let (read, write) = match handles {
        Some(Some(handles)) => handles,
        Some(None) => return Error::ResourceUnavailable.into_raw(),
        None => return Error::NotReady.into_raw(),
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
    if let Err(error) = crate::syscall::copy_to_user_native(output, bytes) {
        let _ = crate::task::with_process_mut(process_id, |process| {
            process.object_handles_mut().close(read);
            process.object_handles_mut().close(write);
        });
        return error.into_raw();
    }
    SUCCESS
}

pub fn launch_value_get(key: u64, output: u64) -> u64 {
    use mnu_abi::status::Error;
    let process_id = match crate::syscall::security::current_process_id() {
        Some(process_id) => process_id,
        None => return Error::NotReady.into_raw(),
    };
    let value = match crate::task::with_process(process_id, |process| {
        process.launch_context().value(key)
    })
    {
        Some(Some(value)) => value,
        Some(None) => return Error::NotFound.into_raw(),
        None => return Error::NotReady.into_raw(),
    };
    match crate::syscall::copy_to_user_native(output, &value.to_ne_bytes()) {
        Ok(()) => SUCCESS,
        Err(error) => error.into_raw(),
    }
}

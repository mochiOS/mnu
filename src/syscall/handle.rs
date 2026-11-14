mod memory;
pub use memory::{memory_object_create, memory_object_length, memory_object_resize};
mod provider_io;
pub(crate) use provider_io::read_all;
use provider_io::*;
mod process;
pub(crate) use process::retain_created_process;
pub use process::{
    process_execution_read, process_memory_read, process_open, process_open_by_id, process_status,
    process_wait,
};
mod process_control;
pub use process_control::{process_resume, process_suspend, process_terminate};
mod wait;
pub use wait::wait_many;
mod context;
pub use context::{
    context_handle_remove, context_handle_set, context_value_remove, context_value_set, launch_get,
};

use crate::ipc::provider::{
    call as provider_call, endpoint as provider_endpoint, memory_object as provider_memory_object,
    read_at as provider_read_at, sync as provider_sync, write_at as provider_write_at,
};
use alloc::sync::{Arc, Weak};

mod snapshot;
pub use snapshot::table_read;
mod process_image;
pub use process_image::read as process_image_read;
mod capture;
pub use capture::table_capture;
mod provider_reference;
pub use provider_reference::count as provider_object_reference_count;
mod memory_update;
pub use memory_update::create as provider_memory_update_create;
pub use memory_update::create_admission as provider_memory_admission_create;

use crate::task::{HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry, ProviderObject};

use super::SUCCESS;

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

pub fn read(raw: u64, buffer: u64, length: u64) -> u64 {
    let object = match object_native(raw, HandleRights::READ) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    crate::task::operation::Scope::with(object, |object| match object {
        KernelObject::File(file) => crate::syscall::fs::read_file_handle(file, buffer, length),
        KernelObject::Provider(provider) => provider_read(provider, buffer, length),
        _ => mnu_abi::status::Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(mnu_abi::status::Error::into_raw)
}

pub fn write(raw: u64, buffer: u64, length: u64) -> u64 {
    let object = match object_native(raw, HandleRights::WRITE) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    crate::task::operation::Scope::with(object, |object| match object {
        KernelObject::File(file) => crate::syscall::fs::write_file_handle(file, buffer, length),
        KernelObject::Provider(provider) => provider_write(provider, buffer, length),
        _ => mnu_abi::status::Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(mnu_abi::status::Error::into_raw)
}

pub fn write_bounded(raw: u64, buffer: u64, length: u64, byte_end: u64) -> u64 {
    let object = match object_native(raw, HandleRights::WRITE) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    crate::task::operation::Scope::with(object, |object| match object {
        KernelObject::Provider(provider) => {
            provider_write_impl(provider, buffer, length, Some(byte_end))
        }
        _ => mnu_abi::status::Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(mnu_abi::status::Error::into_raw)
}

pub fn stream_read(raw: u64, buffer: u64, length: u64, options: u64) -> u64 {
    if options & !mnu_abi::STREAM_READ_OPTIONS_ALL != 0 {
        return mnu_abi::status::Error::InvalidArgument.into_raw();
    }
    let object = match object_native(raw, HandleRights::READ) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    crate::task::operation::Scope::with(object, |object| match object {
        KernelObject::File(file) => {
            crate::syscall::fs::read_stream_handle(file, buffer, length, options)
        }
        _ => mnu_abi::status::Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(mnu_abi::status::Error::into_raw)
}

pub fn stream_write(raw: u64, buffer: u64, length: u64, options: u64) -> u64 {
    if options & !mnu_abi::STREAM_WRITE_OPTIONS_ALL != 0 {
        return mnu_abi::status::Error::InvalidArgument.into_raw();
    }
    let object = match object_native(raw, HandleRights::WRITE) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    crate::task::operation::Scope::with(object, |object| match object {
        KernelObject::File(file) => {
            crate::syscall::fs::write_stream_handle(file, buffer, length, options)
        }
        _ => mnu_abi::status::Error::InvalidArgument.into_raw(),
    })
    .unwrap_or_else(mnu_abi::status::Error::into_raw)
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

    let required = if write {
        HandleRights::WRITE
    } else {
        HandleRights::READ
    };
    let object = match object_native(raw, required) {
        Ok(object @ (KernelObject::Provider(_) | KernelObject::VmObject(_))) => object,
        Ok(object @ KernelObject::HandleSnapshot(_)) if !write => object,
        Ok(object @ KernelObject::Completion(_)) if !write => object,
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
    if !write && length > mnu_abi::provider::MAX_DATA_LEN as u64 {
        if let (KernelObject::Provider(provider), Some(identity)) = (&object, identity) {
            if provider.memory_features() & mnu_abi::provider::MEMORY_FEATURE_READ_AT_SHARED != 0 {
                if let Some(result) =
                    provider_read_shared_at(provider, identity, buffer, length as usize, offset)
                {
                    return result;
                }
            }
        }
    }
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
                return if done == 0 {
                    error.into_raw()
                } else {
                    done as u64
                };
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
                    provider_write_at(provider, position, &data[..chunk])
                        .map_err(crate::result::OperationError::into_raw)
                        .and_then(|count| {
                            if count > chunk {
                                return Err(Error::BackingFailure.into_raw());
                            }
                            if let Some(guard) = &_guard {
                                crate::mem::vm_object::update_provider_range(
                                    guard,
                                    position,
                                    &data[..count],
                                );
                            }
                            Ok(count)
                        })
                } else {
                    provider_read_at(provider, position, &mut data[..chunk])
                        .map_err(crate::result::OperationError::into_raw)
                        .and_then(|count| {
                            if count > chunk {
                                return Err(Error::BackingFailure.into_raw());
                            }
                            if let Some(identity) = identity {
                                crate::mem::vm_object::overlay_provider_range(
                                    provider,
                                    identity,
                                    position,
                                    &mut data[..count],
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
            KernelObject::Completion(receipt) => Ok(receipt.read_at(position, &mut data[..chunk])),
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
                return if done == 0 {
                    error.into_raw()
                } else {
                    done as u64
                };
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
            update,
            control_code,
            input,
            input_length,
            output,
            output_length,
        );
    }
    let KernelObject::Provider(provider) = object else {
        return Error::InvalidArgument.into_raw();
    };
    provider_exchange(
        &provider,
        mnu_abi::provider::OP_CONTROL,
        control_code,
        input,
        input_length,
        output,
        output_length,
    )
}

/// A provider query is explicitly READ-authorized, not a weaker control call.
pub fn query(
    raw: u64,
    code: u64,
    input: u64,
    input_length: u64,
    output: u64,
    output_length: u64,
) -> u64 {
    use mnu_abi::status::Error;
    let object = match object_native(raw, HandleRights::READ) {
        Ok(object) => object,
        Err(error) => return error.into_raw(),
    };
    let KernelObject::Provider(provider) = object else {
        return Error::InvalidArgument.into_raw();
    };
    provider_exchange(
        &provider,
        mnu_abi::provider::OP_QUERY,
        code,
        input,
        input_length,
        output,
        output_length,
    )
}

fn provider_exchange(
    provider: &ProviderObject,
    opcode: u16,
    code: u64,
    input: u64,
    input_length: u64,
    output: u64,
    output_length: u64,
) -> u64 {
    use mnu_abi::status::Error;
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
        opcode,
        object_id: provider.object_id,
        argument: 0,
        basis: code,
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
        match provider_call(provider, request, &input_bytes, &mut response_storage)
            .map_err(crate::result::OperationError::into_raw)
        {
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
    let object = match object_native(raw, HandleRights::empty()) {
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
        .and_then(|thread| crate::ipc::endpoint_for_thread(thread.as_u64()))
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
        .and_then(|thread| crate::ipc::endpoint_for_thread(thread.as_u64()))
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
    }) {
        Some(Some(value)) => value,
        Some(None) => return Error::NotFound.into_raw(),
        None => return Error::NotReady.into_raw(),
    };
    match crate::syscall::copy_to_user_native(output, &value.to_ne_bytes()) {
        Ok(()) => SUCCESS,
        Err(error) => error.into_raw(),
    }
}

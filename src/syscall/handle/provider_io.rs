//! Provider I/O usercopy and bounded transfer adapters.
use super::*;

pub(super) fn provider_cache_identity(provider: &ProviderObject) -> Result<Option<u64>, u64> {
    provider_memory_object(provider)
        .map_err(crate::result::OperationError::into_raw)
        .map(|identity| (identity != 0).then_some(identity))
}

/// The caller retains its backing I/O guard through reading and cache overlay.
pub(super) fn provider_read_chunk<'a>(
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
    let (response, data_len) = provider_call(provider, request, &[], storage)
        .map_err(crate::result::OperationError::into_raw)?;
    let count = usize::try_from(response.value)
        .map_err(|_| mnu_abi::status::Error::BackingFailure.into_raw())?;
    if count > length {
        return Err(mnu_abi::status::Error::BackingFailure.into_raw());
    }
    let data = storage
        .get_mut(wire::RESPONSE_HEADER_LEN..)
        .and_then(|data| data.get_mut(..data_len))
        .ok_or(mnu_abi::status::Error::BackingFailure.into_raw())?;
    if let Some(identity) = identity {
        if data.len() != wire::READ_POSITION_LEN + count {
            return Err(mnu_abi::status::Error::BackingFailure.into_raw());
        }
        let offset = u64::from_le_bytes(
            data[..wire::READ_POSITION_LEN]
                .try_into()
                .map_err(|_| mnu_abi::status::Error::BackingFailure.into_raw())?,
        );
        let data = &mut data[wire::READ_POSITION_LEN..];
        crate::mem::vm_object::overlay_provider_range(provider, identity, offset, data)?;
        Ok(data)
    } else if count == data.len() {
        Ok(data)
    } else {
        Err(mnu_abi::status::Error::BackingFailure.into_raw())
    }
}

struct TemporaryMemoryHandle(u64);

impl Drop for TemporaryMemoryHandle {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

/// None permits inline retry only before any bytes have been read. Some
/// carries a completed count or opaque failure; neither permits replay.
pub(super) fn provider_read_shared(
    provider: &ProviderObject,
    identity: u64,
    buffer: u64,
    length: usize,
) -> Option<u64> {
    provider_read_shared_impl(provider, identity, buffer, length, None)
}

pub(super) fn provider_read_shared_at(
    provider: &ProviderObject,
    identity: u64,
    buffer: u64,
    length: usize,
    offset: u64,
) -> Option<u64> {
    if offset.checked_add(length as u64).is_none() {
        return Some(mnu_abi::status::Error::LimitExceeded.into_raw());
    }
    provider_read_shared_impl(provider, identity, buffer, length, Some(offset))
}

/// Reusable transfer storage for both user copies and owned object snapshots.
/// The producer receives only READ/WRITE/MAP on this anonymous object.
struct ProviderReadTransfer {
    _owned: TemporaryMemoryHandle,
    object: KernelObject,
    handle: ObjectHandle,
}

impl ProviderReadTransfer {
    fn new(capacity: usize) -> Result<Self, u64> {
        use mnu_abi::status::Error;
        if capacity == 0 || capacity > mnu_abi::provider::MAX_SHARED_READ_LEN {
            return Err(Error::InvalidArgument.into_raw());
        }
        let backing_length = (capacity as u64 + 4095) & !4095;
        let raw = memory_object_create(backing_length, 0);
        if (raw as i64) < 0 {
            return Err(raw);
        }
        let owned = TemporaryMemoryHandle(raw);
        let object = match object_native(raw, HandleRights::MAP) {
            Ok(object @ KernelObject::VmObject(_)) => object,
            Ok(_) => return Err(Error::BackingFailure.into_raw()),
            Err(error) => return Err(error.into_raw()),
        };
        let handle = u32::try_from(raw)
            .ok()
            .and_then(ObjectHandle::from_raw)
            .ok_or(Error::BackingFailure.into_raw())?;
        Ok(Self {
            _owned: owned,
            object,
            handle,
        })
    }

    /// The caller holds the backing I/O guard through transfer and overlay.
    /// None is an explicit transport decline; errors never authorize replay.
    fn read_locked(
        &self,
        provider: &ProviderObject,
        identity: u64,
        position: Option<u64>,
        data: &mut [u8],
    ) -> Result<Option<usize>, u64> {
        use mnu_abi::{provider as wire, status::Error};
        let KernelObject::VmObject(object) = &self.object else {
            return Err(Error::BackingFailure.into_raw());
        };
        let position_bytes = position.unwrap_or(0).to_le_bytes();
        let payload = if position.is_some() {
            &position_bytes[..]
        } else {
            &[]
        };
        let request = wire::RequestHeader {
            opcode: if position.is_some() {
                wire::OP_READ_AT_SHARED
            } else {
                wire::OP_READ_SHARED
            },
            object_id: provider.object_id,
            argument: 0,
            basis: 0,
            length: data.len() as u32,
            data_length: payload.len() as u32,
        };
        let mut encoded = [0u8; wire::REQUEST_HEADER_LEN + 8];
        let encoded_length = match request.encode(payload, &mut encoded) {
            Ok(length) => length,
            Err(_) => return Err(Error::InvalidArgument.into_raw()),
        };
        let mut response = [0u8; wire::RESPONSE_HEADER_LEN + wire::READ_POSITION_LEN];
        let reply_length = crate::ipc::call_provider_with_handle_from_kernel(
            provider_endpoint(provider),
            &encoded[..encoded_length],
            &mut response,
            self.handle,
            HandleRights::READ
                .union(HandleRights::WRITE)
                .union(HandleRights::MAP),
        )?;
        let (reply, reply_position) = wire::ResponseHeader::decode(
            response
                .get(..reply_length)
                .ok_or(Error::BackingFailure.into_raw())?,
        )
        .map_err(|_| Error::BackingFailure.into_raw())?;
        if reply.object_id != provider.object_id || reply.opcode != request.opcode {
            return Err(Error::BackingFailure.into_raw());
        }
        if reply.status != 0 {
            return Err(reply.status as u64);
        }
        if reply_position.is_empty() {
            // Only the validated, empty successful reply authorizes a
            // transport change. No error value is feature detection.
            return Ok(None);
        }
        let count = usize::try_from(reply.value).map_err(|_| Error::BackingFailure.into_raw())?;
        if count > data.len() || reply_position.len() != wire::READ_POSITION_LEN {
            return Err(Error::BackingFailure.into_raw());
        }
        let start = u64::from_le_bytes(
            reply_position
                .try_into()
                .map_err(|_| Error::BackingFailure.into_raw())?,
        );
        if position.is_some_and(|position| position != start) {
            return Err(Error::BackingFailure.into_raw());
        }
        if object.read_at(0, &mut data[..count])? != count {
            return Err(Error::BackingFailure.into_raw());
        }
        crate::mem::vm_object::overlay_provider_range(
            provider,
            identity,
            start,
            &mut data[..count],
        )?;
        Ok(Some(count))
    }
}

pub(super) fn provider_read_shared_impl(
    provider: &ProviderObject,
    identity: u64,
    buffer: u64,
    length: usize,
    offset: Option<u64>,
) -> Option<u64> {
    use mnu_abi::{provider as wire, status::Error};
    // A read may return a successful prefix. Bound one syscall to a single
    // shared transfer so a large request cannot monopolize a CPU in kernel
    // mode while unrelated ready threads wait for user-mode preemption.
    let length = length.min(wire::MAX_SHARED_READ_LEN);
    let capacity = length;
    let transfer = match ProviderReadTransfer::new(capacity) {
        Ok(transfer) => transfer,
        Err(error) => return Some(error),
    };
    let mut data = match crate::util::object_snapshot::zeroed_native(capacity) {
        Ok(data) => data,
        Err(error) => return Some(error.into_raw()),
    };
    let mut total = 0usize;
    while total < length {
        let chunk = (length - total).min(capacity);
        // Positioned callers checked the entire source range before entering.
        let position = offset.map(|offset| offset + total as u64);
        let result = (|| {
            let _io_guard = crate::mem::vm_object::lock_provider_io(provider, identity)
                .map_err(mnu_abi::status::Error::into_raw)?;
            transfer.read_locked(provider, identity, position, &mut data[..chunk])
        })();
        let count = match result {
            Ok(Some(count)) => count,
            Ok(None) => return (total != 0).then_some(total as u64),
            Err(error) => return Some(if total == 0 { error } else { total as u64 }),
        };
        // User-buffer faults can read the same object: never retain its I/O
        // serialization guard across this copy.
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => {
                return Some(if total == 0 {
                    Error::InvalidAddress.into_raw()
                } else {
                    total as u64
                });
            }
        };
        if let Err(error) = crate::syscall::copy_to_user_native(address, &data[..count]) {
            return Some(if total == 0 {
                error.into_raw()
            } else {
                total as u64
            });
        }
        total += count;
        if count < chunk {
            break;
        }
    }
    Some(total as u64)
}

pub(super) fn provider_read(provider: &ProviderObject, buffer: u64, length: u64) -> u64 {
    let length = match usize::try_from(length) {
        Ok(length) if length <= isize::MAX as usize => length,
        _ => return mnu_abi::status::Error::LimitExceeded.into_raw(),
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
            // Only a side-effect-free, empty success declines this transport.
            // Errors and completed prefixes must never replay a stream read.
            if let Some(result) = provider_read_shared(provider, identity, buffer, length) {
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
    let mut response_storage = match crate::util::object_snapshot::zeroed_native(
        mnu_abi::provider::RESPONSE_HEADER_LEN + mnu_abi::provider::MAX_DATA_LEN,
    ) {
        Ok(storage) => storage,
        Err(error) => return error.into_raw(),
    };
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
            None => {
                return if total == 0 {
                    mnu_abi::status::Error::InvalidAddress.into_raw()
                } else {
                    total as u64
                };
            }
        };
        if let Err(error) = crate::syscall::copy_to_user_native(address, data) {
            return if total == 0 {
                error.into_raw()
            } else {
                total as u64
            };
        }
        total += data_len;
        if data_len < chunk {
            break;
        }
    }
    total as u64
}

pub(super) fn provider_write(provider: &ProviderObject, buffer: u64, length: u64) -> u64 {
    provider_write_impl(provider, buffer, length, None)
}

pub(super) fn provider_write_impl(
    provider: &ProviderObject,
    buffer: u64,
    length: u64,
    byte_end: Option<u64>,
) -> u64 {
    let length = match usize::try_from(length) {
        Ok(length) if length <= isize::MAX as usize => length,
        _ => return mnu_abi::status::Error::LimitExceeded.into_raw(),
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
        return match provider_call(provider, request, &[], &mut response)
            .map_err(crate::result::OperationError::into_raw)
        {
            Ok((header, data_len @ (0 | 8)))
                if header.value == 0 && (byte_end.is_none() || data_len == 8) =>
            {
                SUCCESS
            }
            Ok(_) => mnu_abi::status::Error::BackingFailure.into_raw(),
            Err(error) => error,
        };
    }
    let identity = match provider_cache_identity(provider) {
        Ok(identity) => identity,
        Err(error) => return error,
    };
    let mut total = 0usize;
    let mut data =
        match crate::util::object_snapshot::zeroed_native(mnu_abi::provider::MAX_DATA_LEN) {
            Ok(data) => data,
            Err(error) => return error.into_raw(),
        };
    let mut response_storage = match crate::util::object_snapshot::zeroed_native(
        mnu_abi::provider::RESPONSE_HEADER_LEN + 8,
    ) {
        Ok(storage) => storage,
        Err(error) => return error.into_raw(),
    };
    while total < length {
        let chunk = (length - total).min(data.len());
        let address = match buffer.checked_add(total as u64) {
            Some(address) => address,
            None => {
                return if total == 0 {
                    mnu_abi::status::Error::InvalidAddress.into_raw()
                } else {
                    total as u64
                };
            }
        };
        if let Err(error) = crate::syscall::copy_from_user_native(address, &mut data[..chunk]) {
            return if total == 0 {
                error.into_raw()
            } else {
                total as u64
            };
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
            match provider_call(provider, request, &data[..chunk], &mut response_storage)
                .map_err(crate::result::OperationError::into_raw)
            {
                Ok(response) => response,
                Err(error) => return if total == 0 { error } else { total as u64 },
            };
        let written = match usize::try_from(response.value) {
            Ok(written)
                if (data_len == 8 || (byte_end.is_none() && data_len == 0)) && written <= chunk =>
            {
                written
            }
            _ => {
                return if total == 0 {
                    mnu_abi::status::Error::BackingFailure.into_raw()
                } else {
                    total as u64
                };
            }
        };
        let mut reached_end = false;
        if written != 0 && data_len == 8 {
            let start = u64::from_le_bytes(
                response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN..]
                    .try_into()
                    .unwrap(),
            );
            if let Some(end) = byte_end {
                let Some(after) = start
                    .checked_add(written as u64)
                    .filter(|after| *after <= end)
                else {
                    return if total == 0 {
                        mnu_abi::status::Error::BackingFailure.into_raw()
                    } else {
                        total as u64
                    };
                };
                reached_end = after == end;
            }
            if let Some(guard) = &_io_guard {
                crate::mem::vm_object::update_provider_range(guard, start, &data[..written]);
            }
        }
        total += written;
        if written < chunk || reached_end {
            break;
        }
    }
    total as u64
}

pub(super) fn provider_seek_result(
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
    match provider_call(provider, request, &[], &mut response_storage)
        .map_err(crate::result::OperationError::into_raw)
    {
        Ok((response, 0)) if response.value <= i64::MAX as u64 => Ok(response.value),
        Ok((_, 0)) => Err(mnu_abi::status::Error::LimitExceeded.into_raw()),
        Ok(_) => Err(mnu_abi::status::Error::BackingFailure.into_raw()),
        Err(error) => Err(error),
    }
}

pub(super) fn provider_seek(
    provider: &ProviderObject,
    offset: i64,
    basis: crate::syscall::fs::SeekBasis,
) -> u64 {
    provider_seek_result(provider, offset, basis).unwrap_or_else(|error| error)
}

/// Reads one positional object into kernel-owned storage without exposing any
/// filesystem path or provider identifier to the caller.
/// Local failures use native statuses; lower I/O failures are propagated intact
/// while the provider/pager error boundary is migrated separately.
pub(crate) fn read_all(raw: u64, maximum_length: usize) -> Result<alloc::vec::Vec<u8>, u64> {
    use mnu_abi::status::Error;

    let readable = object_native(raw, HandleRights::READ).map_err(Error::into_raw)?;
    if let KernelObject::VmObject(memory) = &readable {
        let length = memory
            .memory_length()
            .ok_or(Error::InvalidArgument.into_raw())?;
        return crate::util::object_snapshot::read(length, maximum_length, |bytes| {
            memory.read_at(0, bytes)
        });
    }
    let KernelObject::Provider(provider) = readable else {
        return Err(Error::InvalidArgument.into_raw());
    };
    let identity = provider_cache_identity(&provider)?;
    let capacity = maximum_length.min(mnu_abi::provider::MAX_SHARED_READ_LEN);
    // Declare this owner before the guard so its Handle is reclaimed after
    // releasing backing serialization, on every success and failure path.
    let transfer = if identity.is_some()
        && capacity > mnu_abi::provider::MAX_DATA_LEN
        && provider.memory_features() & mnu_abi::provider::MEMORY_FEATURE_READ_AT_SHARED != 0
    {
        Some(ProviderReadTransfer::new(capacity)?)
    } else {
        None
    };
    let chunk = if transfer.is_some() {
        capacity
    } else {
        mnu_abi::provider::MAX_DATA_LEN
    };
    let mut declined = false;
    let _io_guard = identity
        .map(|identity| crate::mem::vm_object::lock_provider_io(&provider, identity))
        .transpose()
        .map_err(mnu_abi::status::Error::into_raw)?;
    let extent = if identity.is_some() {
        use mnu_abi::provider as wire;
        let request = wire::RequestHeader {
            opcode: wire::OP_QUERY,
            object_id: provider.object_id,
            argument: 0,
            basis: wire::QUERY_BYTE_LENGTH,
            length: 8,
            data_length: 0,
        };
        let mut storage = [0; wire::RESPONSE_HEADER_LEN + 8];
        let (_, length) = provider_call(&provider, request, &[], &mut storage)
            .map_err(crate::result::OperationError::into_raw)?;
        if length != 8 {
            return Err(Error::BackingFailure.into_raw());
        }
        Some(u64::from_le_bytes(
            storage[wire::RESPONSE_HEADER_LEN..].try_into().unwrap(),
        ))
    } else {
        None
    };
    let copy = |offset, bytes: &mut [u8]| {
        if !declined {
            if let (Some(transfer), Some(identity)) = (&transfer, identity) {
                match transfer.read_locked(&provider, identity, Some(offset), bytes)? {
                    Some(count) => return Ok(count),
                    None => declined = true,
                }
            }
        }
        let count = provider_read_at(&provider, offset, bytes)
            .map_err(crate::result::OperationError::into_raw)?;
        if count > bytes.len() {
            return Err(Error::BackingFailure.into_raw());
        }
        if let Some(identity) = identity {
            crate::mem::vm_object::overlay_provider_range(
                &provider,
                identity,
                offset,
                &mut bytes[..count],
            )?;
        }
        Ok(count)
    };
    if let Some(length) = extent {
        crate::util::object_snapshot::read_extent(length, maximum_length, chunk, copy)
    } else {
        crate::util::object_snapshot::read_to_end(maximum_length, chunk, copy)
    }
}

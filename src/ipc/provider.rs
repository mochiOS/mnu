//! Typed provider messages over native endpoint transport; no user pointers.
use crate::task::ProviderObject;

pub(crate) fn flush_releases() {
    let mut releases = crate::task::handle_table::take_provider_releases();
    while let Some(ticket) = releases.pop() {
        let release = *ticket.value();
        let endpoint = crate::ipc::IpcEndpoint {
            thread_id: release.endpoint_thread_id,
            slot: release.endpoint_slot,
            generation: release.endpoint_generation,
        };
        if !crate::ipc::endpoint_is_valid(endpoint) {
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
            && !crate::ipc::send_provider_from_kernel(endpoint, &request)
        {
            crate::task::handle_table::requeue_provider_release(ticket);
        }
    }
}

pub(crate) fn endpoint(provider: &ProviderObject) -> crate::ipc::IpcEndpoint {
    crate::ipc::IpcEndpoint {
        thread_id: provider.endpoint_thread_id,
        slot: provider.endpoint_slot,
        generation: provider.endpoint_generation,
    }
}

pub(crate) fn call(
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
    let response_len = crate::ipc::call_provider_from_kernel(
        endpoint(provider),
        &request[..request_len],
        response_storage,
    )?;
    let (response, data) = mnu_abi::provider::ResponseHeader::decode(
        response_storage
            .get(..response_len)
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
pub(crate) fn read_at(
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
    let (response, data_len) = call(provider, request, &[], &mut response_storage)?;
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
pub(crate) fn write_at(provider: &ProviderObject, offset: u64, input: &[u8]) -> Result<usize, u64> {
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
    let (response, data_len) = call(provider, request, input, &mut response_storage)?;
    let written = usize::try_from(response.value).map_err(|_| Error::BackingFailure.into_raw())?;
    if data_len != 0 || written > input.len() {
        return Err(Error::BackingFailure.into_raw());
    }
    Ok(written)
}

pub(crate) fn sync(provider: &ProviderObject) -> Result<(), u64> {
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
    let (response, data_len) = call(provider, request, &[], &mut response_storage)?;
    if response.value != 0 || data_len != 0 {
        return Err(Error::BackingFailure.into_raw());
    }
    Ok(())
}

pub(crate) fn memory_object(provider: &ProviderObject) -> Result<u64, u64> {
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
    let mut response_storage = [0u8; mnu_abi::provider::RESPONSE_HEADER_LEN + 8];
    let (response, data_len) = call(provider, request, &[], &mut response_storage)?;
    let features = mnu_abi::provider::memory_features(
        response.value,
        &response_storage[mnu_abi::provider::RESPONSE_HEADER_LEN..][..data_len],
    )
    .map_err(|_| Error::BackingFailure.into_raw())?;
    if response.value == 0 {
        provider.set_memory_identity_unavailable();
    } else {
        provider.set_memory_identity(response.value, features);
    }
    Ok(response.value)
}

use mnu_abi::status::Error;
use mnu_abi::{SUCCESS, StorageControlRequest, StorageControlResponse};

use crate::capability::Capability;

const MAX_BLOCK_TRANSFER: usize = 256 * 1024;
const SECTOR_BYTES: usize = 512;

fn block_access_allowed() -> bool {
    crate::syscall::security::caller_has_any_capability(&[Capability::DeviceStorage])
}

fn disk_result(result: i32) -> u64 {
    if result == 0 {
        SUCCESS
    } else {
        (result as i64) as u64
    }
}

pub fn block_read(disk_id: u64, lba: u64, destination: u64, length: u64) -> u64 {
    if !block_access_allowed() {
        return Error::AccessDenied.into_raw();
    }
    let Ok(disk_id) = u32::try_from(disk_id) else {
        return Error::InvalidArgument.into_raw();
    };
    let Ok(length) = usize::try_from(length) else {
        return Error::LimitExceeded.into_raw();
    };
    if length > MAX_BLOCK_TRANSFER {
        return Error::LimitExceeded.into_raw();
    }
    if length == 0 || length % SECTOR_BYTES != 0 {
        return Error::InvalidArgument.into_raw();
    }
    if destination == 0 || destination.checked_add(length as u64 - 1).is_none() {
        return Error::InvalidAddress.into_raw();
    }
    if !crate::cext::disk::is_loaded() {
        return Error::NotReady.into_raw();
    }
    let mut bytes = match crate::util::object_snapshot::zeroed_native(length) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    let result = crate::cext::disk::read_sector(disk_id, lba, &mut bytes);
    if result != 0 {
        return disk_result(result);
    }
    if let Err(error) = crate::syscall::copy_to_user_native(destination, &bytes) {
        return error.into_raw();
    }
    SUCCESS
}

pub fn block_write(disk_id: u64, lba: u64, source: u64, length: u64) -> u64 {
    if !block_access_allowed() {
        return Error::AccessDenied.into_raw();
    }
    let Ok(disk_id) = u32::try_from(disk_id) else {
        return Error::InvalidArgument.into_raw();
    };
    let Ok(length) = usize::try_from(length) else {
        return Error::LimitExceeded.into_raw();
    };
    if length > MAX_BLOCK_TRANSFER {
        return Error::LimitExceeded.into_raw();
    }
    if length == 0 || length % SECTOR_BYTES != 0 {
        return Error::InvalidArgument.into_raw();
    }
    if source == 0 || source.checked_add(length as u64 - 1).is_none() {
        return Error::InvalidAddress.into_raw();
    }
    if !crate::cext::disk::is_loaded() {
        return Error::NotReady.into_raw();
    }
    let mut bytes = match crate::util::object_snapshot::zeroed_native(length) {
        Ok(bytes) => bytes,
        Err(error) => return error.into_raw(),
    };
    if let Err(error) = crate::syscall::copy_from_user_native(source, &mut bytes) {
        return error.into_raw();
    }
    disk_result(crate::cext::disk::write_sector(disk_id, lba, &bytes))
}

pub fn block_flush(disk_id: u64) -> u64 {
    if !block_access_allowed() {
        return Error::AccessDenied.into_raw();
    }
    let Ok(disk_id) = u32::try_from(disk_id) else {
        return Error::InvalidArgument.into_raw();
    };
    if !crate::cext::disk::is_loaded() {
        return Error::NotReady.into_raw();
    }
    disk_result(crate::cext::disk::flush(disk_id))
}

pub fn control(request_ptr: u64, response_ptr: u64) -> u64 {
    control_authorized(request_ptr, response_ptr, "device.storage")
}

pub fn device_control(
    request_ptr: u64,
    response_ptr: u64,
    authority_ptr: u64,
    authority_len: u64,
) -> u64 {
    let mut name = [0u8; 128];
    if authority_len == 0 {
        return Error::InvalidArgument.into_raw();
    }
    if authority_len > name.len() as u64 {
        return Error::LimitExceeded.into_raw();
    }
    if authority_ptr == 0 || authority_ptr.checked_add(authority_len - 1).is_none() {
        return Error::InvalidAddress.into_raw();
    }
    let name = &mut name[..authority_len as usize];
    if let Err(error) = crate::syscall::copy_from_user_native(authority_ptr, name) {
        return error.into_raw();
    }
    let Ok(authority) = core::str::from_utf8(name) else {
        return Error::InvalidArgument.into_raw();
    };
    control_authorized(request_ptr, response_ptr, authority)
}

fn control_authorized(request_ptr: u64, response_ptr: u64, authority: &str) -> u64 {
    let Some(capability) = Capability::from_str(authority) else {
        return Error::AccessDenied.into_raw();
    };
    if !crate::syscall::security::caller_has_any_capability(&[capability]) {
        return Error::AccessDenied.into_raw();
    }
    let mut request_bytes = [0_u8; core::mem::size_of::<StorageControlRequest>()];
    if let Err(error) = crate::syscall::copy_from_user_native(request_ptr, &mut request_bytes) {
        return error.into_raw();
    }
    let request = decode_request(&request_bytes);
    if request.reserved0 != 0 {
        return Error::InvalidArgument.into_raw();
    }
    let response = match crate::platform::device_control(
        authority,
        request.operation,
        request.device_id,
        request.arguments,
    ) {
        Ok(response) => StorageControlResponse {
            status: response.status,
            device_id: response.device_id,
            values: response.values,
        },
        Err(_) => return Error::BackingFailure.into_raw(),
    };
    let bytes = encode_response(response);
    if let Err(error) = crate::syscall::copy_to_user_native(response_ptr, &bytes) {
        return error.into_raw();
    }
    SUCCESS
}

fn decode_request(bytes: &[u8; 40]) -> StorageControlRequest {
    StorageControlRequest {
        operation: u16::from_ne_bytes(bytes[0..2].try_into().unwrap()),
        reserved0: u16::from_ne_bytes(bytes[2..4].try_into().unwrap()),
        device_id: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        arguments: core::array::from_fn(|index| {
            let start = 8 + index * 8;
            u64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap())
        }),
    }
}

fn encode_response(response: StorageControlResponse) -> [u8; 40] {
    let mut bytes = [0_u8; 40];
    bytes[0..4].copy_from_slice(&response.status.to_ne_bytes());
    bytes[4..8].copy_from_slice(&response.device_id.to_ne_bytes());
    for (index, value) in response.values.iter().enumerate() {
        let start = 8 + index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}

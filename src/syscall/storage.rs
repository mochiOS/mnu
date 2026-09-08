use mnu_abi::{StorageControlRequest, StorageControlResponse, SUCCESS};

use crate::capability::Capability;

const EACCES: u64 = (-13_i64) as u64;
const EFAULT: u64 = (-14_i64) as u64;
const EIO: u64 = (-5_i64) as u64;
const EINVAL: u64 = (-22_i64) as u64;

pub fn control(request_ptr: u64, response_ptr: u64) -> u64 {
    control_authorized(request_ptr, response_ptr, "device.storage")
}

pub fn device_control(request_ptr: u64, response_ptr: u64, authority_ptr: u64, authority_len: u64) -> u64 {
    let mut name = [0u8; 128];
    if authority_len == 0 || authority_len > name.len() as u64 {
        return EINVAL;
    }
    let name = &mut name[..authority_len as usize];
    if crate::syscall::copy_from_user(authority_ptr, name).is_err() {
        return EFAULT;
    }
    let Ok(authority) = core::str::from_utf8(name) else { return EINVAL; };
    control_authorized(request_ptr, response_ptr, authority)
}

fn control_authorized(request_ptr: u64, response_ptr: u64, authority: &str) -> u64 {
    let Some(capability) = Capability::from_str(authority) else { return EACCES; };
    if !crate::syscall::security::caller_has_any_capability(&[capability]) {
        return EACCES;
    }
    let mut request_bytes = [0_u8; core::mem::size_of::<StorageControlRequest>()];
    if crate::syscall::copy_from_user(request_ptr, &mut request_bytes).is_err() {
        return EFAULT;
    }
    let request = decode_request(&request_bytes);
    if request.reserved0 != 0 {
        return EINVAL;
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
        Err(_) => return EIO,
    };
    let bytes = encode_response(response);
    if crate::syscall::copy_to_user(response_ptr, &bytes).is_err() {
        return EFAULT;
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

//! Transitional size lookup for the legacy mounted-path namespace.
//! Namespace mutation and POSIX ownership operations belong in user space.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use mochios_filesystem_protocol as protocol;

use crate::syscall::{EINVAL, EIO, ENXIO};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub fn lookup_size(mount_id: u64, path: &str) -> Result<u64, u64> {
    if path.is_empty() || path.len() > protocol::MAX_PATH_LEN {
        return Err(EINVAL);
    }
    let response = call(
        protocol::Header {
            opcode: protocol::OP_LOOKUP,
            mount_id,
            length: path.len() as u32,
            ..protocol::Header::default()
        },
        path.as_bytes(),
        protocol::HEADER_LEN + protocol::METADATA_LEN,
    )?;
    decode_size(response.header, response.payload())
}

struct OwnedResponse {
    header: protocol::Header,
    bytes: Vec<u8>,
    payload_offset: usize,
    payload_len: usize,
}

impl OwnedResponse {
    fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..self.payload_offset + self.payload_len]
    }
}

fn call(
    mut header: protocol::Header,
    payload: &[u8],
    reply_capacity: usize,
) -> Result<OwnedResponse, u64> {
    header.request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let request_id = header.request_id;
    let mut request = vec![0u8; protocol::HEADER_LEN + payload.len()];
    let request_len = protocol::encode(header, payload, &mut request).map_err(|_| EINVAL)?;
    let endpoint =
        crate::vfs::userspace_endpoint(crate::vfs::MountId(header.mount_id)).ok_or(ENXIO)?;
    let mut reply = vec![0u8; reply_capacity.max(protocol::HEADER_LEN)];
    let reply_len =
        crate::syscall::ipc::call_from_kernel(endpoint, &request[..request_len], &mut reply)?;
    reply.truncate(reply_len);
    let (response, response_payload) = protocol::decode(&reply).map_err(|_| EIO)?;
    if response.opcode != protocol::OP_STATUS || response.request_id != request_id {
        return Err(EIO);
    }
    if response.status < 0 {
        return Err((response.status as i64) as u64);
    }
    let payload_offset = protocol::HEADER_LEN;
    let payload_len = response_payload.len();
    Ok(OwnedResponse {
        header: response,
        bytes: reply,
        payload_offset,
        payload_len,
    })
}

fn decode_size(header: protocol::Header, payload: &[u8]) -> Result<u64, u64> {
    // Validate the transitional response, but do not retain POSIX ownership
    // or access bits in the kernel's object description.
    protocol::decode_metadata(payload).map_err(|_| EIO)?;
    Ok(header.offset)
}

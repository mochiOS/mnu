//! Transitional transport for legacy vnode I/O and size queries.
//! Namespace mutation and POSIX ownership operations belong in user space.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use mochios_filesystem_protocol as protocol;

use crate::syscall::{EINVAL, EIO, ENXIO};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: u64,
    pub size: u64,
    pub kind: u32,
}

pub fn lookup(mount_id: u64, path: &str) -> Result<NodeInfo, u64> {
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
    node_info(response.header, response.payload())
}

pub fn close(mount_id: u64, open_id: u64) -> Result<(), u64> {
    call(
        protocol::Header {
            opcode: protocol::OP_CLOSE,
            mount_id,
            open_id,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN,
    )?;
    Ok(())
}

pub fn read(mount_id: u64, open_id: u64, offset: u64, output: &mut [u8]) -> Result<usize, u64> {
    if output.len() > protocol::MAX_IO_LEN {
        return Err(EINVAL);
    }
    let response = call(
        protocol::Header {
            opcode: protocol::OP_READ,
            mount_id,
            open_id,
            offset,
            flags: output.len() as u32,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN + output.len(),
    )?;
    output[..response.payload().len()].copy_from_slice(response.payload());
    Ok(response.payload().len())
}

pub fn write(mount_id: u64, open_id: u64, offset: u64, input: &[u8]) -> Result<usize, u64> {
    if input.len() > protocol::MAX_IO_LEN {
        return Err(EINVAL);
    }
    let response = call(
        protocol::Header {
            opcode: protocol::OP_WRITE,
            mount_id,
            open_id,
            offset,
            length: input.len() as u32,
            ..protocol::Header::default()
        },
        input,
        protocol::HEADER_LEN,
    )?;
    usize::try_from(response.header.offset).map_err(|_| EIO)
}

pub fn stat(mount_id: u64, node_id: u64, open_id: u64) -> Result<NodeInfo, u64> {
    let response = call(
        protocol::Header {
            opcode: protocol::OP_STAT,
            mount_id,
            node_id,
            open_id,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN + protocol::METADATA_LEN,
    )?;
    node_info(response.header, response.payload())
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

fn node_info(header: protocol::Header, payload: &[u8]) -> Result<NodeInfo, u64> {
    // Validate the transitional response, but do not retain POSIX ownership
    // or access bits in the kernel's object description.
    protocol::decode_metadata(payload).map_err(|_| EIO)?;
    Ok(NodeInfo {
        node_id: header.node_id,
        size: header.offset,
        kind: header.flags,
    })
}

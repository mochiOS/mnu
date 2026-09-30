//! Kernel transport for the userspace filesystem service.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use mochios_filesystem_protocol as protocol;

use crate::syscall::{EINVAL, EIO, ENXIO};

const SERVICE_NAME: &str = "filesystem.service";

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: u64,
    pub size: u64,
    pub mode: u32,
    pub kind: u32,
}

pub fn mount(mount_id: u64) -> Result<NodeInfo, u64> {
    let response = call(
        protocol::Header {
            opcode: protocol::OP_MOUNT,
            mount_id,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN,
    )?;
    Ok(node_info(response.header))
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
        protocol::HEADER_LEN,
    )?;
    Ok(node_info(response.header))
}

pub fn open(mount_id: u64, node_id: u64, flags: u32) -> Result<u64, u64> {
    let response = call(
        protocol::Header {
            opcode: protocol::OP_OPEN,
            mount_id,
            node_id,
            flags,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN,
    )?;
    Ok(response.header.open_id)
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
        protocol::HEADER_LEN,
    )?;
    Ok(node_info(response.header))
}

pub fn create(mount_id: u64, path: &str, mode: u32, kind: u32) -> Result<NodeInfo, u64> {
    if path.is_empty() || path.len() > protocol::MAX_PATH_LEN {
        return Err(EINVAL);
    }
    let response = call(
        protocol::Header {
            opcode: protocol::OP_CREATE,
            mount_id,
            length: path.len() as u32,
            flags: kind,
            mode,
            ..protocol::Header::default()
        },
        path.as_bytes(),
        protocol::HEADER_LEN,
    )?;
    Ok(node_info(response.header))
}

pub fn truncate(mount_id: u64, open_id: u64, size: u64) -> Result<(), u64> {
    call(
        protocol::Header {
            opcode: protocol::OP_TRUNCATE,
            mount_id,
            open_id,
            offset: size,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN,
    )?;
    Ok(())
}

pub fn read_link(mount_id: u64, node_id: u64) -> Result<Vec<u8>, u64> {
    let response = call(
        protocol::Header {
            opcode: protocol::OP_READLINK,
            mount_id,
            node_id,
            ..protocol::Header::default()
        },
        &[],
        protocol::MAX_MESSAGE_LEN,
    )?;
    Ok(response.payload().to_vec())
}

pub fn sync(mount_id: u64) -> Result<(), u64> {
    call(
        protocol::Header {
            opcode: protocol::OP_SYNC,
            mount_id,
            ..protocol::Header::default()
        },
        &[],
        protocol::HEADER_LEN,
    )?;
    Ok(())
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
    let endpoint = service_endpoint().ok_or(ENXIO)?;
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

fn node_info(header: protocol::Header) -> NodeInfo {
    NodeInfo {
        node_id: header.node_id,
        size: header.offset,
        mode: header.mode,
        kind: header.flags,
    }
}

fn service_endpoint() -> Option<u64> {
    let process_id = crate::task::find_process_id_by_name(SERVICE_NAME)?;
    let mut thread_id = None;
    crate::task::for_each_thread(|thread| {
        if thread_id.is_none()
            && thread.process_id() == process_id
            && thread.state() != crate::task::ThreadState::Terminated
        {
            thread_id = Some(thread.id().as_u64());
        }
    });
    thread_id.and_then(crate::syscall::ipc::ensure_endpoint_handle_for_thread)
}

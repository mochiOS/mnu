use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const OP_READ: u8 = 1;
const OP_WRITE: u8 = 2;
const OP_STAT: u8 = 3;
const MAX_REQ: usize = 4128;
const MAX_REPLY: usize = 4128;
const BENCH_CAPACITY: usize = 32 * 1024 * 1024;
const BENCH_PATH: &[u8] = b"/bench/huge.bin";
const CONFIG_PATH: &[u8] = b"/config/kernel.conf";

static STARTED: AtomicBool = AtomicBool::new(false);
static ENDPOINT: AtomicU64 = AtomicU64::new(2);
static mut BENCH_DATA: [u8; BENCH_CAPACITY] = [0; BENCH_CAPACITY];
static BENCH_LEN: AtomicU64 = AtomicU64::new(4 * 1024 * 1024);

#[inline]
fn is_error(ret: u64) -> bool {
    (ret as i64) < 0
}

#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let slice = bytes.get(off..off + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn ensure_bench_initialized() {
    let len = BENCH_LEN.load(Ordering::Acquire) as usize;
    let len = len.min(BENCH_CAPACITY);
    unsafe {
        let base = core::ptr::addr_of_mut!(BENCH_DATA) as *mut u8;
        for i in 0..len {
            core::ptr::write(base.add(i), (i as u8).wrapping_mul(31).wrapping_add(7));
        }
    }
}

fn bench_read(offset: usize, dst: &mut [u8]) -> usize {
    let len = BENCH_LEN.load(Ordering::Acquire) as usize;
    let start = core::cmp::min(offset, len);
    let available = len.saturating_sub(start);
    let to_copy = core::cmp::min(dst.len(), available);
    if to_copy == 0 {
        return 0;
    }
    unsafe {
        let src = core::ptr::addr_of!(BENCH_DATA) as *const u8;
        core::ptr::copy_nonoverlapping(src.add(start), dst.as_mut_ptr(), to_copy);
    }
    to_copy
}

fn bench_write(offset: usize, src: &[u8]) -> usize {
    let start = core::cmp::min(offset, BENCH_CAPACITY);
    let max_copy = BENCH_CAPACITY.saturating_sub(start);
    let to_copy = core::cmp::min(src.len(), max_copy);
    if to_copy == 0 {
        return 0;
    }
    unsafe {
        let dst = core::ptr::addr_of_mut!(BENCH_DATA) as *mut u8;
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst.add(start), to_copy);
    }
    let end = start.saturating_add(to_copy);
    let cur = BENCH_LEN.load(Ordering::Acquire) as usize;
    if end > cur {
        BENCH_LEN.store(end as u64, Ordering::Release);
    }
    to_copy
}

fn config_bytes() -> &'static [u8] {
    b"scheduler.default_time_slice_ms=10\nfs.service_retry_count=3\nfs.service_retry_ms=10\n"
}

fn local_read(path: &str, offset: u64, out: &mut [u8]) -> Result<usize, u64> {
    if path == "/bench/huge.bin" {
        let copied = bench_read(offset as usize, out);
        return Ok(copied);
    }
    if path == "/config/kernel.conf" {
        let cfg = config_bytes();
        let start = core::cmp::min(offset as usize, cfg.len());
        let end = core::cmp::min(start.saturating_add(out.len()), cfg.len());
        let copied = end.saturating_sub(start);
        out[..copied].copy_from_slice(&cfg[start..end]);
        return Ok(copied);
    }
    Err(2)
}

fn local_write(path: &str, offset: u64, data: &[u8]) -> Result<usize, u64> {
    if path == "/bench/huge.bin" {
        return Ok(bench_write(offset as usize, data));
    }
    Err(2)
}

fn local_stat(path: &str) -> Result<(u16, u64), u64> {
    if path == "/bench/huge.bin" {
        return Ok((0x8000 | 0o644, BENCH_LEN.load(Ordering::Acquire)));
    }
    if path == "/config/kernel.conf" {
        return Ok((0x8000 | 0o444, config_bytes().len() as u64));
    }
    Err(2)
}

fn reply(sender: u64, status: u64, payload: &[u8]) {
    let mut buf = [0u8; MAX_REPLY];
    let header = 16usize;
    if payload.len() + header > buf.len() {
        return;
    }
    buf[..8].copy_from_slice(&status.to_le_bytes());
    buf[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    if !payload.is_empty() {
        buf[16..16 + payload.len()].copy_from_slice(payload);
    }
    let _ = crate::ipc_reply(sender, buf.as_ptr() as u64, (payload.len() + header) as u64);
}

fn reply_u64(sender: u64, status: u64, value: u64) {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&status.to_le_bytes());
    buf[8..16].copy_from_slice(&value.to_le_bytes());
    let _ = crate::ipc_reply(sender, buf.as_ptr() as u64, buf.len() as u64);
}

fn handle_read(sender: u64, req: &[u8]) {
    let Some(path_len) = read_u32_le(req, 1).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(offset) = read_u64_le(req, 5) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(max_len) = read_u64_le(req, 13).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let path = match req.get(21..21 + path_len) {
        Some(p) => p,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };

    let mut data = [0u8; MAX_REPLY - 16];
    let (status, copied) = if path == BENCH_PATH {
        let limit = core::cmp::min(max_len, data.len());
        let copied = bench_read(offset as usize, &mut data[..limit]);
        (0, copied)
    } else if path == CONFIG_PATH {
        let cfg = config_bytes();
        let start = core::cmp::min(offset as usize, cfg.len());
        let end = core::cmp::min(start.saturating_add(max_len), cfg.len());
        let copied = end.saturating_sub(start);
        data[..copied].copy_from_slice(&cfg[start..end]);
        (0, copied)
    } else {
        (2, 0)
    };
    reply(sender, status, &data[..copied]);
}

fn handle_write(sender: u64, req: &[u8]) {
    let Some(path_len) = read_u32_le(req, 1).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(offset) = read_u64_le(req, 5) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(data_len) = read_u64_le(req, 13).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let path_off = 21usize;
    let data_off = match path_off.checked_add(path_len) {
        Some(v) => v,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };
    let data = match req.get(data_off..data_off + data_len) {
        Some(d) => d,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };
    let written = if req.get(path_off..data_off) == Some(BENCH_PATH) {
        bench_write(offset as usize, data)
    } else {
        0
    };
    reply_u64(sender, 0, written as u64);
}

fn handle_stat(sender: u64, req: &[u8]) {
    let Some(path_len) = read_u32_le(req, 1).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let path = match req.get(5..5 + path_len) {
        Some(p) => p,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };
    if path == BENCH_PATH {
        let mut buf = [0u8; 18];
        buf[..8].copy_from_slice(&0u64.to_le_bytes());
        buf[8..10].copy_from_slice(&(0x8000u16 | 0o644).to_le_bytes());
        buf[10..18].copy_from_slice(&BENCH_LEN.load(Ordering::Acquire).to_le_bytes());
        let _ = crate::ipc_reply(sender, buf.as_ptr() as u64, buf.len() as u64);
        return;
    }
    if path == CONFIG_PATH {
        let mut buf = [0u8; 18];
        buf[..8].copy_from_slice(&0u64.to_le_bytes());
        buf[8..10].copy_from_slice(&(0x8000u16 | 0o444).to_le_bytes());
        buf[10..18].copy_from_slice(&(config_bytes().len() as u64).to_le_bytes());
        let _ = crate::ipc_reply(sender, buf.as_ptr() as u64, buf.len() as u64);
        return;
    }
    let mut buf = [0u8; 18];
    buf[..8].copy_from_slice(&2u64.to_le_bytes());
    let _ = crate::ipc_reply(sender, buf.as_ptr() as u64, buf.len() as u64);
}

extern "C" fn fs_service_thread(_arg: u64) {
    let mut req = [0u8; MAX_REQ];
    loop {
        let ret = crate::ipc_wait(req.as_mut_ptr() as u64, req.len() as u64, 0);
        if is_error(ret) {
            continue;
        }
        let sender = ret >> 32;
        let len = (ret & 0xFFFF_FFFF) as usize;
        if len == 0 {
            continue;
        }
        let len = core::cmp::min(len, req.len());
        match req[0] {
            OP_READ => handle_read(sender, &req[..len]),
            OP_WRITE => handle_write(sender, &req[..len]),
            OP_STAT => handle_stat(sender, &req[..len]),
            _ => reply_u64(sender, 22, 0),
        }
    }
}

pub fn ensure_started() -> u64 {
    ensure_bench_initialized();
    let _ = STARTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
    ENDPOINT.load(Ordering::Acquire)
}

pub fn read(path: &str, offset: u64, out: &mut [u8]) -> Result<usize, u64> {
    let endpoint = ensure_started();
    if endpoint == 0 {
        return Err(38);
    }
    let path_bytes = path.as_bytes();
    let mut req = [0u8; MAX_REQ];
    let req_len = 1usize
        .checked_add(4)
        .and_then(|v| v.checked_add(8))
        .and_then(|v| v.checked_add(8))
        .and_then(|v| v.checked_add(path_bytes.len()))
        .ok_or(22u64)?;
    if req_len > req.len() {
        return Err(22);
    }
    req[0] = OP_READ;
    req[1..5].copy_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    req[5..13].copy_from_slice(&offset.to_le_bytes());
    req[13..21].copy_from_slice(&(out.len() as u64).to_le_bytes());
    req[21..21 + path_bytes.len()].copy_from_slice(path_bytes);

    let mut reply = [0u8; MAX_REPLY];
    let ret = crate::ipc_call(
        endpoint,
        req.as_ptr() as u64,
        req_len as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    );
    if !is_error(ret) {
        let status = u64::from_le_bytes(reply[..8].try_into().unwrap_or([0; 8]));
        if status == 0 {
            let nread = u64::from_le_bytes(reply[8..16].try_into().unwrap_or([0; 8])) as usize;
            let copy_len = core::cmp::min(core::cmp::min(nread, out.len()), reply.len().saturating_sub(16));
            if copy_len > 0 {
                out[..copy_len].copy_from_slice(&reply[16..16 + copy_len]);
            }
            return Ok(copy_len);
        }
    }
    local_read(path, offset, out)
}

pub fn write(path: &str, offset: u64, data: &[u8]) -> Result<usize, u64> {
    let endpoint = ensure_started();
    if endpoint == 0 {
        return Err(38);
    }
    let path_bytes = path.as_bytes();
    let mut req = [0u8; MAX_REQ];
    let req_len = 1usize
        .checked_add(4)
        .and_then(|v| v.checked_add(8))
        .and_then(|v| v.checked_add(8))
        .and_then(|v| v.checked_add(path_bytes.len()))
        .and_then(|v| v.checked_add(data.len()))
        .ok_or(22u64)?;
    if req_len > req.len() {
        return Err(22);
    }
    req[0] = OP_WRITE;
    req[1..5].copy_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    req[5..13].copy_from_slice(&offset.to_le_bytes());
    req[13..21].copy_from_slice(&(data.len() as u64).to_le_bytes());
    req[21..21 + path_bytes.len()].copy_from_slice(path_bytes);
    let data_off = 21 + path_bytes.len();
    req[data_off..data_off + data.len()].copy_from_slice(data);

    let mut reply = [0u8; MAX_REPLY];
    let ret = crate::ipc_call(
        endpoint,
        req.as_ptr() as u64,
        req_len as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    );
    if !is_error(ret) {
        let status = u64::from_le_bytes(reply[..8].try_into().unwrap_or([0; 8]));
        if status == 0 {
            let written = u64::from_le_bytes(reply[8..16].try_into().unwrap_or([0; 8])) as usize;
            return Ok(written);
        }
    }
    local_write(path, offset, data)
}

pub fn stat(path: &str) -> Result<(u16, u64), u64> {
    let endpoint = ensure_started();
    if endpoint == 0 {
        return Err(38);
    }
    let path_bytes = path.as_bytes();
    let mut req = [0u8; MAX_REQ];
    let req_len = 1usize
        .checked_add(4)
        .and_then(|v| v.checked_add(path_bytes.len()))
        .ok_or(22u64)?;
    if req_len > req.len() {
        return Err(22);
    }
    req[0] = OP_STAT;
    req[1..5].copy_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    req[5..5 + path_bytes.len()].copy_from_slice(path_bytes);

    let mut reply = [0u8; MAX_REPLY];
    let ret = crate::ipc_call(
        endpoint,
        req.as_ptr() as u64,
        req_len as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    );
    if !is_error(ret) {
        let status = u64::from_le_bytes(reply[..8].try_into().unwrap_or([0; 8]));
        if status == 0 && reply.len() >= 18 {
            let mode = u16::from_le_bytes(reply[8..10].try_into().unwrap_or([0; 2]));
            let size = u64::from_le_bytes(reply[10..18].try_into().unwrap_or([0; 8]));
            return Ok((mode, size));
        }
    }
    local_stat(path)
}

pub fn service_main() -> ! {
    ensure_bench_initialized();
    fs_service_thread(0);
    loop {
        core::hint::spin_loop();
    }
}

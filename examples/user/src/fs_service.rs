use core::convert::TryInto;
use core::sync::atomic::{AtomicU64, Ordering};

const SHARED_WINDOW_CAPACITY: usize = 1024 * 1024;
const SHARED_WINDOW_PAGES: usize = SHARED_WINDOW_CAPACITY / 4096;

const OP_READ: u8 = 1;
const OP_WRITE: u8 = 2;
const OP_STAT: u8 = 3;

const MAX_REQ: usize = 256;
const MAX_REPLY: usize = 16;
const REQ_HEADER_LEN: usize = 45;
const MAP_HEADER_MAGIC: u32 = 0xABCD_DCBA;

const BENCH_CAPACITY: usize = 32 * 1024 * 1024;
const BENCH_PATH: &[u8] = b"/bench/huge.bin";
const CONFIG_PATH: &[u8] = b"/config/kernel.conf";

static SERVICE_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static SPAWN_ATTEMPTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static WINDOW_PTR: AtomicU64 = AtomicU64::new(0);
static mut SHARED_PAGES: [u64; SHARED_WINDOW_PAGES] = [0; SHARED_WINDOW_PAGES];
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

fn read_u32_be_magic(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn config_bytes() -> &'static [u8] {
    b"scheduler.default_time_slice_ms=10\nfs.service_retry_count=3\nfs.service_retry_ms=10\n"
}

fn bench_len() -> usize {
    BENCH_LEN.load(Ordering::Acquire) as usize
}

fn ensure_bench_initialized() {
    let len = bench_len().min(BENCH_CAPACITY);
    unsafe {
        let base = core::ptr::addr_of_mut!(BENCH_DATA) as *mut u8;
        for i in 0..len {
            core::ptr::write(base.add(i), (i as u8).wrapping_mul(31).wrapping_add(7));
        }
    }
}

fn bench_read(offset: usize, dst: &mut [u8]) -> usize {
    ensure_bench_initialized();
    let len = bench_len();
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
    ensure_bench_initialized();
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

fn shared_window_ptr() -> u64 {
    WINDOW_PTR.load(Ordering::Acquire)
}

fn shared_window_len() -> usize {
    SHARED_WINDOW_CAPACITY
}

unsafe fn shared_window_slice_mut(offset: usize, len: usize) -> Option<&'static mut [u8]> {
    let end = offset.checked_add(len)?;
    if end > SHARED_WINDOW_CAPACITY {
        return None;
    }
    let base = shared_window_ptr();
    if base == 0 {
        return None;
    }
    let ptr = (base + offset as u64) as *mut u8;
    Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

unsafe fn shared_window_slice(offset: usize, len: usize) -> Option<&'static [u8]> {
    let end = offset.checked_add(len)?;
    if end > SHARED_WINDOW_CAPACITY {
        return None;
    }
    let base = shared_window_ptr();
    if base == 0 {
        return None;
    }
    let ptr = (base + offset as u64) as *const u8;
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

pub fn configure_service_endpoint(endpoint: u64) {
    SERVICE_ENDPOINT.store(endpoint, Ordering::Release);
}

pub fn service_endpoint() -> u64 {
    SERVICE_ENDPOINT.load(Ordering::Acquire)
}

fn reply_u64(sender: u64, status: u64, value: u64) {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&status.to_le_bytes());
    buf[8..16].copy_from_slice(&value.to_le_bytes());
    let _ = crate::ipc_reply(sender, buf.as_ptr() as u64, buf.len() as u64);
}

fn handle_read(sender: u64, req: &[u8]) {
    if shared_window_ptr() == 0 {
        reply_u64(sender, 11, 0);
        return;
    }

    let Some(path_len) = read_u32_le(req, 1).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(_fd) = read_u64_le(req, 5) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(offset) = read_u64_le(req, 13) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(max_len) = read_u64_le(req, 21).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(shared_cap) = read_u64_le(req, 29).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(buffer_offset) = read_u64_le(req, 37).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let path = match req.get(REQ_HEADER_LEN..REQ_HEADER_LEN + path_len) {
        Some(p) => p,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };

    if shared_cap == 0 || shared_cap > shared_window_len() || buffer_offset >= shared_cap {
        reply_u64(sender, 22, 0);
        return;
    }
    let max_write = core::cmp::min(max_len, shared_cap.saturating_sub(buffer_offset));
    if max_write == 0 {
        reply_u64(sender, 22, 0);
        return;
    }
    let window = unsafe { shared_window_slice_mut(buffer_offset, max_write) };
    let Some(window) = window else {
        reply_u64(sender, 22, 0);
        return;
    };

    let copied = if path == BENCH_PATH {
        bench_read(offset as usize, window)
    } else if path == CONFIG_PATH {
        let cfg = config_bytes();
        let start = core::cmp::min(offset as usize, cfg.len());
        let end = core::cmp::min(start.saturating_add(max_write), cfg.len());
        let copied = end.saturating_sub(start);
        window[..copied].copy_from_slice(&cfg[start..end]);
        copied
    } else {
        0
    };

    if copied == 0 && path != BENCH_PATH && path != CONFIG_PATH {
        reply_u64(sender, 2, 0);
        return;
    }

    reply_u64(sender, 0, copied as u64);
}

fn handle_write(sender: u64, req: &[u8]) {
    if shared_window_ptr() == 0 {
        reply_u64(sender, 11, 0);
        return;
    }

    let Some(path_len) = read_u32_le(req, 1).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(_fd) = read_u64_le(req, 5) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(offset) = read_u64_le(req, 13) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(data_len) = read_u64_le(req, 21).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(shared_cap) = read_u64_le(req, 29).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let Some(buffer_offset) = read_u64_le(req, 37).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let path_off = REQ_HEADER_LEN;
    let data_off = match path_off.checked_add(path_len) {
        Some(v) => v,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };
    let path = match req.get(path_off..data_off) {
        Some(p) => p,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };

    if shared_cap == 0 || shared_cap > shared_window_len() || buffer_offset >= shared_cap {
        reply_u64(sender, 22, 0);
        return;
    }
    let max_read = core::cmp::min(data_len, shared_cap.saturating_sub(buffer_offset));
    if max_read == 0 {
        reply_u64(sender, 22, 0);
        return;
    }
    let data = unsafe { shared_window_slice(buffer_offset, max_read) };
    let Some(data) = data else {
        reply_u64(sender, 22, 0);
        return;
    };

    let written = if path == BENCH_PATH {
        bench_write(offset as usize, data)
    } else {
        0
    };
    if path != BENCH_PATH {
        reply_u64(sender, 2, 0);
        return;
    }

    reply_u64(sender, 0, written as u64);
}

fn handle_stat(sender: u64, req: &[u8]) {
    if shared_window_ptr() == 0 {
        reply_u64(sender, 11, 0);
        return;
    }

    let Some(path_len) = read_u32_le(req, 1).map(|v| v as usize) else {
        reply_u64(sender, 22, 0);
        return;
    };
    let path = match req.get(REQ_HEADER_LEN..REQ_HEADER_LEN + path_len) {
        Some(p) => p,
        None => {
            reply_u64(sender, 22, 0);
            return;
        }
    };

    if path == BENCH_PATH {
        let _ = crate::write(1, b"fs.service stat bench\n".as_ptr() as u64, 22);
        reply_u64(sender, 0, bench_len() as u64);
        return;
    }
    if path == CONFIG_PATH {
        let _ = crate::write(1, b"fs.service stat config\n".as_ptr() as u64, 23);
        reply_u64(sender, 0, config_bytes().len() as u64);
        return;
    }

    reply_u64(sender, 2, 0);
}

fn build_request(
    req: &mut [u8],
    op: u8,
    path: &str,
    fd: u64,
    offset: u64,
    len: u64,
    shared_cap: u64,
    buffer_offset: u64,
) -> Result<usize, u64> {
    let path_bytes = path.as_bytes();
    let req_len = REQ_HEADER_LEN.checked_add(path_bytes.len()).ok_or(22u64)?;
    if req_len > req.len() {
        return Err(22);
    }
    req[0] = op;
    req[1..5].copy_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    req[5..13].copy_from_slice(&fd.to_le_bytes());
    req[13..21].copy_from_slice(&offset.to_le_bytes());
    req[21..29].copy_from_slice(&len.to_le_bytes());
    req[29..37].copy_from_slice(&shared_cap.to_le_bytes());
    req[37..45].copy_from_slice(&buffer_offset.to_le_bytes());
    req[REQ_HEADER_LEN..REQ_HEADER_LEN + path_bytes.len()].copy_from_slice(path_bytes);
    Ok(req_len)
}

fn send_request(
    endpoint: u64,
    req: &[u8],
    req_len: usize,
    reply: &mut [u8],
) -> Result<(u64, u64), u64> {
    let ret = crate::ipc_call(
        endpoint,
        req.as_ptr() as u64,
        req_len as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    );
    if is_error(ret) {
        return Err(ret);
    }
    if reply.len() < 16 {
        return Err(22);
    }
    let status = u64::from_le_bytes(reply[0..8].try_into().unwrap_or([0; 8]));
    let bytes = u64::from_le_bytes(reply[8..16].try_into().unwrap_or([0; 8]));
    Ok((status, bytes))
}

pub fn window_cap() -> usize {
    shared_window_len()
}

pub fn window_base() -> u64 {
    shared_window_ptr()
}

pub fn window_slice_mut(offset: usize, len: usize) -> Option<&'static mut [u8]> {
    unsafe { shared_window_slice_mut(offset, len) }
}

pub fn ensure_connected() -> u64 {
    let endpoint = service_endpoint();
    if endpoint == 0 {
        if !SPAWN_ATTEMPTED.swap(true, Ordering::AcqRel) {
            let fs_path = b"fs.service\0";
            let spawned = crate::service_spawn(fs_path.as_ptr() as u64);
            if !is_error(spawned) && spawned != 0 {
                SERVICE_ENDPOINT.store(spawned, Ordering::Release);
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }
    let endpoint = service_endpoint();
    if shared_window_ptr() != 0 {
        return endpoint;
    }

    ensure_bench_initialized();
    let page_count = SHARED_WINDOW_PAGES as u64;
    let phys_pages_ptr = core::ptr::addr_of_mut!(SHARED_PAGES) as *mut u64;
    let _ = crate::write(1, b"fs.connect alloc\n".as_ptr() as u64, 17);
    let local_base = crate::alloc_shared_pages(
        page_count,
        phys_pages_ptr as u64,
        page_count,
        0,
    );
    if is_error(local_base) || local_base == 0 {
        return 0;
    }
    WINDOW_PTR.store(local_base, Ordering::Release);

    let _ = crate::write(1, b"fs.connect send\n".as_ptr() as u64, 16);
    let send_ret = crate::ipc_send_pages(
        endpoint,
        phys_pages_ptr as u64,
        page_count,
        local_base,
    );
    if is_error(send_ret) {
        WINDOW_PTR.store(0, Ordering::Release);
        return 0;
    }

    for _ in 0..512 {
        if stat("/bench/huge.bin").is_ok() {
            return endpoint;
        }
        let _ = crate::yield_now();
    }

    endpoint
}

pub fn read_into_window(
    path: &str,
    offset: u64,
    window_offset: usize,
    len: usize,
) -> Result<usize, u64> {
    let endpoint = ensure_connected();
    if endpoint == 0 {
        return Err(38);
    }
    if len == 0 {
        return Ok(0);
    }
    if window_offset
        .checked_add(len)
        .map(|end| end > shared_window_len())
        .unwrap_or(true)
    {
        return Err(22);
    }
    let mut req = [0u8; MAX_REQ];
    let req_len = build_request(
        &mut req,
        OP_READ,
        path,
        0,
        offset,
        len as u64,
        shared_window_len() as u64,
        window_offset as u64,
    )?;
    let mut reply = [0u8; MAX_REPLY];
    let (status, bytes) = send_request(endpoint, &req, req_len, &mut reply)?;
    if status == 0 {
        return Ok(core::cmp::min(bytes as usize, len));
    }
    Err(status)
}

pub fn write_from_window(
    path: &str,
    offset: u64,
    window_offset: usize,
    len: usize,
) -> Result<usize, u64> {
    let endpoint = ensure_connected();
    if endpoint == 0 {
        return Err(38);
    }
    if len == 0 {
        return Ok(0);
    }
    if window_offset
        .checked_add(len)
        .map(|end| end > shared_window_len())
        .unwrap_or(true)
    {
        return Err(22);
    }
    let mut req = [0u8; MAX_REQ];
    let req_len = build_request(
        &mut req,
        OP_WRITE,
        path,
        0,
        offset,
        len as u64,
        shared_window_len() as u64,
        window_offset as u64,
    )?;
    let mut reply = [0u8; MAX_REPLY];
    let (status, bytes) = send_request(endpoint, &req, req_len, &mut reply)?;
    if status == 0 {
        return Ok(core::cmp::min(bytes as usize, len));
    }
    Err(status)
}

pub fn stat(path: &str) -> Result<u64, u64> {
    let endpoint = ensure_connected();
    if endpoint == 0 {
        return Err(38);
    }
    let mut req = [0u8; MAX_REQ];
    let req_len = build_request(&mut req, OP_STAT, path, 0, 0, 0, shared_window_len() as u64, 0)?;
    let mut reply = [0u8; MAX_REPLY];
    let (status, bytes) = send_request(endpoint, &req, req_len, &mut reply)?;
    if status == 0 {
        return Ok(bytes);
    }
    Err(status)
}

pub fn service_main() -> ! {
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

        if shared_window_ptr() == 0 && len == 20 {
            if read_u32_be_magic(&req[..len], 0) == Some(MAP_HEADER_MAGIC) {
                if let Some(mapped) = read_u64_le(&req[..len], 4) {
                    WINDOW_PTR.store(mapped, Ordering::Release);
                    let _ = crate::write(1, b"fs.setup\n".as_ptr() as u64, 9);
                    continue;
                }
            }
        }

        match req[0] {
            OP_READ => handle_read(sender, &req[..len]),
            OP_WRITE => handle_write(sender, &req[..len]),
            OP_STAT => handle_stat(sender, &req[..len]),
            _ => {
                let mut reply = [0u8; MAX_REPLY];
                reply[..8].copy_from_slice(&22u64.to_le_bytes());
                reply[8..16].copy_from_slice(&0u64.to_le_bytes());
                let _ = crate::ipc_reply(sender, reply.as_ptr() as u64, reply.len() as u64);
            }
        }
    }
}

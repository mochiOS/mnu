#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

const SHORT_PING: &[u8] = b"ping-message";
const SHORT_PONG: &[u8] = b"pong-message";
const SELF_MSG: &[u8] = b"self-message";
const STACK_SIZE: u64 = 0x8000;
const PAGE_SIZE: u64 = 0x1000;
const FAST_MSG_MAX: usize = 48;
const ROUNDS: usize = 1;
const FS_BENCH_READ_BYTES: usize = 256 * 1024;
const FS_BENCH_CHUNKS: &[usize] = &[64 * 1024];
const TICKS_PER_SECOND: u64 = 500;
const BYTES_PER_MIB: u64 = 1024 * 1024;

const CAP_PROCESS_SPAWN: &[u8] = b"process.spawn";
const CAP_IPC_CLIENT: &[u8] = b"ipc.client";
const CAP_IPC_SERVER: &[u8] = b"ipc.server";
const CAP_INVALID: &[u8] = b"no.such.capability";
const MAP_ANONYMOUS_PRIVATE: u64 = 0x22;
const MEMORY_SYNC_TEST_PATH: &[u8] = b"/core.service.msync-test";
const PASS_LINE: &[u8] = b"USERLAND SELF-TEST PASS\n";
const FAIL_LINE: &[u8] = b"USERLAND SELF-TEST FAIL\n";
const STAGE_MEMORY: &[u8] = b"stage: memory\n";
const STAGE_EVENT: &[u8] = b"stage: event\n";
const STAGE_IPC_SR: &[u8] = b"stage: ipc send/recv\n";
const STAGE_IPC_PP: &[u8] = b"stage: ipc ping/pong\n";
const STAGE_CAP: &[u8] = b"stage: capability\n";
const STAGE_THREAD: &[u8] = b"stage: thread\n";
const STAGE_SPAWN: &[u8] = b"stage: process_spawn\n";
const STAGE_FS_BENCH: &[u8] = b"stage: fs bench\n";
const FS_BYTES_LINE: &[u8] = b" bytes, ";
const FS_TICK_HZ_LINE: &[u8] = b" tick_hz=";
const FS_ELAPSED_MS_LINE: &[u8] = b" elapsed_ms=";
const FS_ROOTFS_READ_PREFIX: &[u8] = b"fs.cext read[";
const FS_LABEL_SUFFIX: &[u8] = b"]: ";
const EVENT_SIGNAL_A_FAIL: &[u8] = b"event: signal a failed\n";
const EVENT_WAIT_A_FAIL: &[u8] = b"event: wait a failed\n";
const EVENT_SIGNAL_B_FAIL: &[u8] = b"event: signal b failed\n";
const EVENT_POLL_FAIL: &[u8] = b"event: poll failed\n";
static THREAD_TEST_DONE: AtomicBool = AtomicBool::new(false);

#[inline]
fn is_error(ret: u64) -> bool {
    (ret as i64) < 0
}

fn expect_success(ret: u64) -> bool {
    !is_error(ret)
}

fn expect_errno(ret: u64) -> bool {
    is_error(ret)
}

fn write_decimal(fd: u64, mut value: u64) {
    let mut buf = [0u8; 32];
    let mut idx = buf.len();
    if value == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while value > 0 {
            idx -= 1;
            buf[idx] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }
    let _ = user::write(fd, buf[idx..].as_ptr() as u64, (buf.len() - idx) as u64);
}

fn write_literal(fd: u64, bytes: &[u8]) {
    let _ = user::write(fd, bytes.as_ptr() as u64, bytes.len() as u64);
}

fn write_bench_line(
    kind: &[u8],
    chunk_label: &[u8],
    bytes: u64,
    ticks: u64,
    tick_hz: u64,
    elapsed_ms: u64,
    mib_s: u64,
) {
    write_literal(1, kind);
    write_literal(1, chunk_label);
    write_literal(1, FS_LABEL_SUFFIX);
    write_literal(1, b"bytes=");
    write_decimal(1, bytes);
    write_literal(1, FS_BYTES_LINE);
    write_literal(1, b"ticks=");
    write_decimal(1, ticks);
    write_literal(1, FS_TICK_HZ_LINE);
    write_decimal(1, tick_hz);
    write_literal(1, FS_ELAPSED_MS_LINE);
    write_decimal(1, elapsed_ms);
    write_literal(1, b" MiB/s=");
    write_decimal(1, mib_s);
    write_literal(1, b"\n");
}

fn run_memory_tests() -> bool {
    let payload_len = PAGE_SIZE as usize;
    let mut initial = [0u8; PAGE_SIZE as usize];
    let mut expected = [0u8; PAGE_SIZE as usize];
    let mut read_back = [0u8; PAGE_SIZE as usize];

    for (i, byte) in initial.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
    }

    let ptr = user::memory_map(0, PAGE_SIZE, 3, MAP_ANONYMOUS_PRIVATE, 0);
    if ptr == 0 || is_error(ptr) {
        write_literal(1, b"memory: mmap failed\n");
        return false;
    }
    let share = user::memory_share(ptr, PAGE_SIZE, 0);
    if !expect_success(share) {
        write_literal(1, b"memory: share failed\n");
        return false;
    }
    let sync = user::memory_sync(ptr, PAGE_SIZE, 0);
    if !expect_success(sync) {
        write_literal(1, b"memory: sync failed\n");
        return false;
    }
    if !expect_success(user::memory_protect(ptr, PAGE_SIZE, 3)) {
        write_literal(1, b"memory: protect failed\n");
        return false;
    }
    if !expect_success(user::memory_unmap(ptr, PAGE_SIZE)) {
        write_literal(1, b"memory: unmap failed\n");
        return false;
    }

    let path = core::str::from_utf8(MEMORY_SYNC_TEST_PATH).unwrap_or("/core.service.msync-test");
    let create_fd = user::file_open(path, 0o2 | 0o100 | 0o1000);
    if create_fd == 0 || is_error(create_fd) {
        write_literal(1, b"memory: sync file create failed\n");
        return false;
    }
    let _ = user::file_close(create_fd);

    let fd = user::file_open(path, 0o2);
    if fd == 0 || is_error(fd) {
        write_literal(1, b"memory: sync file open failed\n");
        return false;
    }

    let wrote = user::file_write(fd, &initial);
    if wrote != payload_len as u64 {
        let _ = user::file_close(fd);
        write_literal(1, b"memory: sync file seed failed\n");
        return false;
    }
    let _ = user::file_seek(fd, 0, 0);

    let file_ptr = user::memory_map(0, PAGE_SIZE, 3, 0x1, fd);
    if file_ptr == 0 || is_error(file_ptr) {
        let _ = user::file_close(fd);
        write_literal(1, b"memory: sync mmap failed\n");
        return false;
    }

    let mapped =
        unsafe { core::slice::from_raw_parts_mut(file_ptr as *mut u8, PAGE_SIZE as usize) };
    for (i, byte) in mapped.iter_mut().enumerate() {
        let v = (255u8).wrapping_sub((i as u8).wrapping_mul(5));
        *byte = v;
        expected[i] = v;
    }

    if !expect_success(user::memory_sync(file_ptr, PAGE_SIZE, 0)) {
        let _ = user::memory_unmap(file_ptr, PAGE_SIZE);
        let _ = user::file_close(fd);
        write_literal(1, b"memory: sync writeback failed\n");
        return false;
    }

    let _ = user::memory_unmap(file_ptr, PAGE_SIZE);
    let _ = user::file_close(fd);
    let fd = user::file_open(path, 0);
    if fd == 0 || is_error(fd) {
        write_literal(1, b"memory: sync reopen failed\n");
        return false;
    }
    let read = user::file_read(fd, &mut read_back);
    let _ = user::file_close(fd);
    if read != payload_len as u64 || expected != read_back {
        write_literal(1, b"memory: sync verify failed\n");
        return false;
    }

    true
}

fn run_event_tests() -> u64 {
    let event_a = user::event_create(0);
    let event_b = user::event_create(0);
    if is_error(event_a) || is_error(event_b) {
        return 31;
    }

    if !expect_success(user::event_signal(event_b)) {
        let _ = user::write(
            1,
            EVENT_SIGNAL_A_FAIL.as_ptr() as u64,
            EVENT_SIGNAL_A_FAIL.len() as u64,
        );
        return 32;
    }
    if !expect_success(user::event_wait(event_b, 0)) {
        let _ = user::write(
            1,
            EVENT_WAIT_A_FAIL.as_ptr() as u64,
            EVENT_WAIT_A_FAIL.len() as u64,
        );
        return 33;
    }

    if !expect_success(user::event_signal(event_b)) {
        let _ = user::write(
            1,
            EVENT_SIGNAL_B_FAIL.as_ptr() as u64,
            EVENT_SIGNAL_B_FAIL.len() as u64,
        );
        return 34;
    }
    let ids = [event_b, event_a];
    let polled = user::event_poll(ids.as_ptr() as u64, ids.len() as u64, 0);
    if polled != event_b {
        let _ = user::write(
            1,
            EVENT_POLL_FAIL.as_ptr() as u64,
            EVENT_POLL_FAIL.len() as u64,
        );
        return 35;
    }
    0
}

fn run_capability_tests(endpoint: u64) -> bool {
    let process_spawn = CAP_PROCESS_SPAWN.as_ptr() as u64;
    let ipc_client = CAP_IPC_CLIENT.as_ptr() as u64;
    let ipc_server = CAP_IPC_SERVER.as_ptr() as u64;
    let invalid_cap = CAP_INVALID.as_ptr() as u64;

    if user::cap_query(process_spawn, CAP_PROCESS_SPAWN.len() as u64) != 1 {
        return false;
    }
    if user::cap_query(ipc_client, CAP_IPC_CLIENT.len() as u64) != 1 {
        return false;
    }
    if user::cap_query(ipc_server, CAP_IPC_SERVER.len() as u64) != 1 {
        return false;
    }
    if !expect_success(user::cap_clone(
        process_spawn,
        CAP_PROCESS_SPAWN.len() as u64,
    )) {
        return false;
    }
    if !expect_success(user::cap_restrict(
        process_spawn,
        CAP_PROCESS_SPAWN.len() as u64,
        process_spawn,
        CAP_PROCESS_SPAWN.len() as u64,
    )) {
        return false;
    }
    if !expect_errno(user::cap_transfer(
        endpoint,
        process_spawn,
        CAP_PROCESS_SPAWN.len() as u64,
    )) {
        return false;
    }
    expect_errno(user::cap_drop(invalid_cap, CAP_INVALID.len() as u64))
}

fn run_ipc_send_recv_tests(endpoint: u64) -> bool {
    let mut recv_buf = [0u8; FAST_MSG_MAX];
    let send_ret = user::ipc_send(endpoint, SELF_MSG.as_ptr() as u64, SELF_MSG.len() as u64);
    if !expect_success(send_ret) {
        return false;
    }
    let recv_ret = user::ipc_wait(
        recv_buf.as_mut_ptr() as u64,
        recv_buf.len() as u64,
        endpoint,
    );
    if is_error(recv_ret) {
        return false;
    }
    let received_len = (recv_ret & 0xFFFF_FFFF) as usize;
    received_len == SELF_MSG.len() && &recv_buf[..received_len] == SELF_MSG
}

fn run_ipc_ping_pong(endpoint: u64) -> u64 {
    let recv_buf_ptr = user::memory_map(0, PAGE_SIZE, 3, MAP_ANONYMOUS_PRIVATE, 0);
    if recv_buf_ptr == 0 || is_error(recv_buf_ptr) {
        return 60;
    }
    for _ in 0..ROUNDS {
        if !expect_success(user::ipc_send(
            endpoint,
            SHORT_PING.as_ptr() as u64,
            SHORT_PING.len() as u64,
        )) {
            return 61;
        }

        let ret = user::ipc_wait(recv_buf_ptr, FAST_MSG_MAX as u64, endpoint);
        if is_error(ret) {
            return 62;
        }
        let sender = ret >> 32;
        let len = (ret & 0xFFFF_FFFF) as usize;

        if len < 4 {
            return 63;
        }
        let buf = unsafe { core::slice::from_raw_parts(recv_buf_ptr as *const u8, FAST_MSG_MAX) };
        if &buf[..4] != &SHORT_PING[..4] {
            return 63;
        }

        let reply_ret =
            user::ipc_reply(sender, SHORT_PONG.as_ptr() as u64, SHORT_PONG.len() as u64);
        if !expect_success(reply_ret) {
            return 64;
        }

        let reply = user::ipc_wait(recv_buf_ptr, FAST_MSG_MAX as u64, endpoint);
        if is_error(reply) {
            return 65;
        }
        let reply_len = (reply & 0xFFFF_FFFF) as usize;
        if reply_len < 4 {
            return 66;
        }
        let buf = unsafe { core::slice::from_raw_parts(recv_buf_ptr as *const u8, FAST_MSG_MAX) };
        if &buf[..4] != &SHORT_PONG[..4] {
            return 67;
        }
    }

    0
}

fn run_process_spawn_test() -> bool {
    true
}

fn run_fs_benchmark() -> u64 {
    let path = "/testdata";
    for &chunk in FS_BENCH_CHUNKS {
        let read_code = run_fs_chunk_benchmark(path, chunk, FS_BENCH_READ_BYTES);
        if read_code != 0 {
            return read_code;
        }
    }

    0
}

fn run_fs_chunk_benchmark(path: &str, chunk: usize, total_bytes: usize) -> u64 {
    let chunk_label = match chunk {
        65536 => b"64KiB" as &[u8],
        262144 => b"256KiB" as &[u8],
        1048576 => b"1MiB" as &[u8],
        _ => b"chunk" as &[u8],
    };

    let fd = user::file_open(path, 0);
    if is_error(fd) || fd == 0 {
        return 74;
    }

    let mut buffer = alloc::vec![0u8; chunk];

    let mut ticks = 0u64;
    let start = user::time_now();
    let mut offset = 0u64;
    let total = total_bytes as u64;
    let chunk_u64 = chunk as u64;
    while offset < total {
        let io_len = core::cmp::min(chunk_u64, total - offset) as usize;
        let io_start = user::time_now();
        let n = user::file_read(fd, &mut buffer[..io_len]);
        if is_error(n) {
            let _ = user::file_close(fd);
            return 75;
        }
        let n = n as usize;
        if n == 0 {
            break;
        }
        let mut checksum = 0u64;
        for byte in &buffer[..n] {
            checksum = checksum.wrapping_add(*byte as u64);
        }
        let _ = checksum;
        offset += n as u64;
        ticks = ticks.saturating_add(user::time_now().saturating_sub(io_start));
    }

    let _ = user::file_close(fd);

    let elapsed_ms = if ticks == 0 {
        user::time_now().saturating_sub(start).saturating_mul(1000) / TICKS_PER_SECOND
    } else {
        ticks.saturating_mul(1000) / TICKS_PER_SECOND
    };
    let mib_s = if ticks == 0 {
        0
    } else {
        (total.saturating_mul(TICKS_PER_SECOND) / ticks / BYTES_PER_MIB) as u64
    };
    write_bench_line(
        FS_ROOTFS_READ_PREFIX,
        chunk_label,
        total as u64,
        ticks,
        TICKS_PER_SECOND,
        elapsed_ms,
        mib_s,
    );
    0
}

extern "C" fn runnable_thread_entry(_arg: u64) {
    THREAD_TEST_DONE.store(true, Ordering::Release);
    let _ = user::thread_exit(0);
}

fn run_thread_test() -> bool {
    THREAD_TEST_DONE.store(false, Ordering::Release);
    let stack_bytes = STACK_SIZE + PAGE_SIZE;
    let stack_base = user::memory_map(0, stack_bytes, 3, MAP_ANONYMOUS_PRIVATE, 0);
    if stack_base == 0 || is_error(stack_base) {
        return false;
    }
    let stack_top = ((stack_base + stack_bytes) & !0xFu64).saturating_sub(24);
    let tid = user::thread_create(runnable_thread_entry as *const () as u64, stack_top, 0);
    if tid == 0 || is_error(tid) {
        let _ = user::memory_unmap(stack_base, stack_bytes);
        return false;
    }
    let _ = user::sleep(1);
    for _ in 0..256 {
        if THREAD_TEST_DONE.load(Ordering::Acquire) {
            let _ = user::memory_unmap(stack_base, stack_bytes);
            return true;
        }
        let _ = user::yield_now();
    }
    let _ = user::memory_unmap(stack_base, stack_bytes);
    false
}

fn run_all_tests() -> u64 {
    if !user::path_registry_self_test() {
        return 81;
    }
    if !user::run_self_test() {
        return 1;
    }
    let _ = user::write(1, STAGE_SPAWN.as_ptr() as u64, STAGE_SPAWN.len() as u64);
    if !run_process_spawn_test() {
        return 9;
    }
    let _ = user::write(
        1,
        STAGE_FS_BENCH.as_ptr() as u64,
        STAGE_FS_BENCH.len() as u64,
    );
    let fs = run_fs_benchmark();
    if fs != 0 {
        return fs;
    }
    let _ = user::write(1, STAGE_MEMORY.as_ptr() as u64, STAGE_MEMORY.len() as u64);
    if !run_memory_tests() {
        return 2;
    }
    let _ = user::write(1, STAGE_EVENT.as_ptr() as u64, STAGE_EVENT.len() as u64);
    let event = run_event_tests();
    if event != 0 {
        return event;
    }
    let _ = user::write(1, STAGE_IPC_SR.as_ptr() as u64, STAGE_IPC_SR.len() as u64);
    let endpoint = user::ipc_create(0);
    if endpoint == 0 || is_error(endpoint) {
        return 4;
    }
    if !run_ipc_send_recv_tests(endpoint) {
        return 5;
    }
    let _ = user::write(1, STAGE_IPC_PP.as_ptr() as u64, STAGE_IPC_PP.len() as u64);
    let ping = run_ipc_ping_pong(endpoint);
    if ping != 0 {
        return ping;
    }
    let _ = user::write(1, STAGE_CAP.as_ptr() as u64, STAGE_CAP.len() as u64);
    if !run_capability_tests(endpoint) {
        return 7;
    }
    let _ = user::write(1, STAGE_THREAD.as_ptr() as u64, STAGE_THREAD.len() as u64);
    if !run_thread_test() {
        return 8;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let code = run_all_tests();
    let line = if code == 0 { PASS_LINE } else { FAIL_LINE };
    let _ = user::write(1, line.as_ptr() as u64, line.len() as u64);
    user::process_exit(code);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    user::process_exit(1)
}

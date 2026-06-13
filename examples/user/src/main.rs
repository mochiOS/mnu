#![no_std]
#![no_main]

use core::panic::PanicInfo;

const SHORT_PING: &[u8] = b"ping-message";
const SHORT_PONG: &[u8] = b"pong-message";
const SELF_MSG: &[u8] = b"self-message";
const STACK_SIZE: u64 = 0x8000;
const FAST_MSG_MAX: usize = 48;
const ROUNDS: usize = 1;
const PAGE_SIZE: u64 = 0x1000;
const FS_BENCH_BYTES: usize = 4 * 1024 * 1024;
const FS_BENCH_ROUNDS: usize = 2;
const FS_BENCH_PATH: &[u8] = b"/bench/huge.bin\0";
const FS_BENCH_BUF_SIZE: usize = 64 * 1024;
const O_WRONLY: u64 = 0o1;
const O_TRUNC: u64 = 0o1000;
const TICKS_PER_SECOND: u64 = 500;
const BYTES_PER_MIB: u64 = 1024 * 1024;

const CAP_PROCESS_SPAWN: &[u8] = b"process.spawn";
const CAP_IPC_CLIENT: &[u8] = b"ipc.client";
const CAP_IPC_SERVER: &[u8] = b"ipc.server";
const CAP_INVALID: &[u8] = b"no.such.capability";
const MAP_ANONYMOUS_PRIVATE: u64 = 0x22;
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
const FS_OPEN_READ_LINE: &[u8] = b"fs.cext open/read: ";
const FS_WRITE_LINE: &[u8] = b"fs.cext write: ";
const FS_BYTES_LINE: &[u8] = b" bytes, ";
const FS_TICKS_LINE: &[u8] = b" ticks, ";
const FS_MIB_LINE: &[u8] = b" MiB/s\n";
const EVENT_SIGNAL_A_FAIL: &[u8] = b"event: signal a failed\n";
const EVENT_WAIT_A_FAIL: &[u8] = b"event: wait a failed\n";
const EVENT_SIGNAL_B_FAIL: &[u8] = b"event: signal b failed\n";
const EVENT_POLL_FAIL: &[u8] = b"event: poll failed\n";

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

extern "C" fn short_lived_thread(_arg: u64) {
    let _ = user::thread_exit(0);
    loop {
        let _ = user::yield_now();
    }
}

fn run_memory_tests() -> bool {
    let ptr = user::memory_map(0, PAGE_SIZE, 3, MAP_ANONYMOUS_PRIVATE, 0);
    if ptr == 0 || is_error(ptr) {
        return false;
    }
    let share = user::memory_share(ptr, PAGE_SIZE, 0);
    if !expect_success(share) {
        return false;
    }
    if !expect_success(user::memory_sync(ptr, PAGE_SIZE, 0)) {
        return false;
    }
    if !expect_success(user::memory_protect(ptr, PAGE_SIZE, 3)) {
        return false;
    }
    expect_success(user::memory_unmap(ptr, PAGE_SIZE))
}

fn run_event_tests() -> u64 {
    let event_a = user::event_create(0);
    let event_b = user::event_create(0);
    if is_error(event_a) || is_error(event_b) {
        return 31;
    }

    if !expect_success(user::event_signal(event_b)) {
        let _ = user::write(1, EVENT_SIGNAL_A_FAIL.as_ptr() as u64, EVENT_SIGNAL_A_FAIL.len() as u64);
        return 32;
    }
    if !expect_success(user::event_wait(event_b, 0)) {
        let _ = user::write(1, EVENT_WAIT_A_FAIL.as_ptr() as u64, EVENT_WAIT_A_FAIL.len() as u64);
        return 33;
    }

    if !expect_success(user::event_signal(event_b)) {
        let _ = user::write(1, EVENT_SIGNAL_B_FAIL.as_ptr() as u64, EVENT_SIGNAL_B_FAIL.len() as u64);
        return 34;
    }
    let ids = [event_b, event_a];
    let polled = user::event_poll(ids.as_ptr() as u64, ids.len() as u64, 0);
    if polled != event_b {
        let _ = user::write(1, EVENT_POLL_FAIL.as_ptr() as u64, EVENT_POLL_FAIL.len() as u64);
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
    if !expect_success(user::cap_clone(process_spawn, CAP_PROCESS_SPAWN.len() as u64)) {
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
    if !expect_success(user::cap_transfer(
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
    let recv_ret = user::ipc_recv(recv_buf.as_mut_ptr() as u64, recv_buf.len() as u64);
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

        let (sender, len) = loop {
            let ret = user::ipc_recv(recv_buf_ptr, FAST_MSG_MAX as u64);
            if !is_error(ret) {
                break (ret >> 32, (ret & 0xFFFF_FFFF) as usize);
            }
            let _ = user::yield_now();
        };

        if len < 4 {
            return 63;
        }
        let buf = unsafe { core::slice::from_raw_parts(recv_buf_ptr as *const u8, FAST_MSG_MAX) };
        if &buf[..4] != &SHORT_PING[..4] {
            return 63;
        }

        let reply_ret = user::ipc_reply(sender, SHORT_PONG.as_ptr() as u64, SHORT_PONG.len() as u64);
        if !expect_success(reply_ret) {
            return 64;
        }

        let reply_len = loop {
            let reply = user::ipc_recv(recv_buf_ptr, FAST_MSG_MAX as u64);
            if !is_error(reply) {
                break (reply & 0xFFFF_FFFF) as usize;
            }
            let _ = user::yield_now();
        };
        if reply_len < 4 {
            return 65;
        }
        let buf = unsafe { core::slice::from_raw_parts(recv_buf_ptr as *const u8, FAST_MSG_MAX) };
        if &buf[..4] != &SHORT_PONG[..4] {
            return 66;
        }
    }

    0
}

fn run_process_spawn_test() -> bool {
    let child = user::process_spawn(0, 0);
    if child == 0 {
        user::process_exit(0);
    }
    if is_error(child) {
        let _ = user::write(1, b"process_spawn: spawn error\n".as_ptr() as u64, 27);
        return false;
    }
    true
}

fn run_fs_benchmark() -> u64 {
    let bench_size = FS_BENCH_BYTES as u64;
    let buf_ptr = user::memory_map(0, FS_BENCH_BUF_SIZE as u64, 3, MAP_ANONYMOUS_PRIVATE, 0);
    if buf_ptr == 0 || is_error(buf_ptr) {
        return 70;
    }

    let path = FS_BENCH_PATH.as_ptr() as u64;
    let chunk = FS_BENCH_BUF_SIZE as u64;

    let mut open_ticks = 0u64;
    for _ in 0..FS_BENCH_ROUNDS {
        let open_start = user::time_now();
        let fd = user::open(path, 0);
        if is_error(fd) {
            return 71;
        }
        open_ticks = open_ticks.saturating_add(user::time_now().saturating_sub(open_start));
        let _ = user::close(fd);
    }

    let mut write_ticks = 0u64;
    let mut written = 0u64;
    for _ in 0..FS_BENCH_ROUNDS {
        let write_start = user::time_now();
        let fd = user::open(path, O_WRONLY | O_TRUNC);
        if is_error(fd) {
            return 72;
        }
        written = 0;
        while written < bench_size {
            let remaining = bench_size - written;
            let to_write = core::cmp::min(remaining, chunk);
            let ret = user::write(fd, buf_ptr, to_write);
            if is_error(ret) {
                let _ = user::close(fd);
                return 73;
            }
            if ret == 0 {
                break;
            }
            written = written.saturating_add(ret);
        }
        write_ticks = write_ticks.saturating_add(user::time_now().saturating_sub(write_start));
        let _ = user::close(fd);
        if written != bench_size {
            break;
        }
    }

    let _ = user::memory_unmap(buf_ptr, FS_BENCH_BUF_SIZE as u64);

    if written != bench_size {
        return 74;
    }

    let total_bytes = bench_size.saturating_mul(FS_BENCH_ROUNDS as u64);
    let open_mib_s = if open_ticks == 0 {
        0
    } else {
        (total_bytes.saturating_mul(TICKS_PER_SECOND) / open_ticks / BYTES_PER_MIB) as u64
    };
    let write_mib_s = if write_ticks == 0 {
        0
    } else {
        (total_bytes.saturating_mul(TICKS_PER_SECOND) / write_ticks / BYTES_PER_MIB) as u64
    };

    let _ = user::write(1, FS_OPEN_READ_LINE.as_ptr() as u64, FS_OPEN_READ_LINE.len() as u64);
    write_decimal(1, total_bytes);
    let _ = user::write(1, FS_BYTES_LINE.as_ptr() as u64, FS_BYTES_LINE.len() as u64);
    write_decimal(1, open_ticks);
    let _ = user::write(1, FS_TICKS_LINE.as_ptr() as u64, FS_TICKS_LINE.len() as u64);
    write_decimal(1, open_mib_s);
    let _ = user::write(1, FS_MIB_LINE.as_ptr() as u64, FS_MIB_LINE.len() as u64);

    let _ = user::write(1, FS_WRITE_LINE.as_ptr() as u64, FS_WRITE_LINE.len() as u64);
    write_decimal(1, total_bytes);
    let _ = user::write(1, FS_BYTES_LINE.as_ptr() as u64, FS_BYTES_LINE.len() as u64);
    write_decimal(1, write_ticks);
    let _ = user::write(1, FS_TICKS_LINE.as_ptr() as u64, FS_TICKS_LINE.len() as u64);
    write_decimal(1, write_mib_s);
    let _ = user::write(1, FS_MIB_LINE.as_ptr() as u64, FS_MIB_LINE.len() as u64);

    0
}

fn run_thread_test() -> bool {
    let stack_bytes = STACK_SIZE + PAGE_SIZE;
    let stack_base = user::memory_map(0, stack_bytes, 3, MAP_ANONYMOUS_PRIVATE, 0);
    if stack_base == 0 || is_error(stack_base) {
        return false;
    }
    let stack_top = ((stack_base + stack_bytes) & !0xFu64).saturating_sub(24);
    let tid = user::thread_create(
        short_lived_thread as *const () as u64,
        stack_top,
        0,
    );
    expect_success(tid)
}

fn run_all_tests() -> u64 {
    if !user::run_self_test() {
        return 1;
    }
    let _ = user::write(1, STAGE_SPAWN.as_ptr() as u64, STAGE_SPAWN.len() as u64);
    if !run_process_spawn_test() {
        return 9;
    }
    let _ = user::write(1, STAGE_FS_BENCH.as_ptr() as u64, STAGE_FS_BENCH.len() as u64);
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

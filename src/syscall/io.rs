//! I/O関連のシステムコール

use super::types::{EFAULT, EINVAL, EPERM, SUCCESS};
use crate::capability::Capability;
use crate::util::console;
use crate::{debug, error, info, warn};

fn caller_has_port_io_access() -> bool {
    crate::syscall::security::caller_has_any_capability(&[
        Capability::UsbAccess,
        Capability::DeviceInput,
        Capability::DeviceGpu,
        Capability::DeviceNet,
        Capability::SerialAccess,
    ])
}

/// Writes raw bytes to the kernel's early diagnostic console.
///
/// This is a native debugging mechanism, not a POSIX file descriptor or
/// standard-stream operation. Normal application I/O uses object handles.
pub fn debug_write(buf_ptr: u64, len: u64) -> u64 {
    if len == 0 {
        return SUCCESS;
    }
    if buf_ptr == 0 {
        return EFAULT;
    }

    let mut buf = alloc::vec![0u8; len as usize];
    if let Err(err) = crate::syscall::copy_from_user(buf_ptr, &mut buf) {
        return err;
    }

    // シリアルには常に出力する（デバッグ用）
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut serial = console::SERIAL.lock();
        for &byte in &buf {
            serial.send_byte(byte);
        }
    });

    if let Ok(text) = core::str::from_utf8(&buf) {
        crate::util::vga::print(format_args!("{}", text));
    }

    len
}

/// Logシステムコール
///
/// カーネルログにメッセージを書き込む
/// # 引数
/// msg: メッセージ
/// len: メッセージの長さ
/// level: ログレベル（0=ERROR、1=WARNING、2=INFO、3=DEBUG）
///
/// # 戻り値
/// 成功時はSUCCESS、エラー時はエラーコード
pub fn log(msg: u64, len: u64, level: u64) -> u64 {
    if msg == 0 || len == 0 {
        return super::types::EINVAL;
    }

    let mut copied = alloc::vec![0u8; len as usize];
    if let Err(err) = crate::syscall::copy_from_user(msg, &mut copied) {
        return err;
    }

    let msg = match core::str::from_utf8(&copied) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    match level {
        0 => error!("{}", msg),
        1 => warn!("{}", msg),
        2 => info!("{}", msg),
        3 => debug!("{}", msg),
        _ => return EINVAL,
    }
    SUCCESS
}

fn read_port_u8(port: u16) -> u8 {
    unsafe {
        let mut io_port = x86_64::instructions::port::Port::<u8>::new(port);
        io_port.read()
    }
}

fn read_port_u16(port: u16) -> u16 {
    unsafe {
        let mut io_port = x86_64::instructions::port::Port::<u16>::new(port);
        io_port.read()
    }
}

fn read_port_u32(port: u16) -> u32 {
    unsafe {
        let mut io_port = x86_64::instructions::port::Port::<u32>::new(port);
        io_port.read()
    }
}

fn write_port_u8(port: u16, value: u8) {
    unsafe {
        let mut io_port = x86_64::instructions::port::Port::<u8>::new(port);
        io_port.write(value);
    }
}

fn write_port_u16(port: u16, value: u16) {
    unsafe {
        let mut io_port = x86_64::instructions::port::Port::<u16>::new(port);
        io_port.write(value);
    }
}

fn write_port_u32(port: u16, value: u32) {
    unsafe {
        let mut io_port = x86_64::instructions::port::Port::<u32>::new(port);
        io_port.write(value);
    }
}

pub fn port_in(port: u64, width: u64) -> u64 {
    if !caller_has_port_io_access() {
        return EPERM;
    }
    let port = port as u16;
    match width {
        1 => read_port_u8(port) as u64,
        2 => read_port_u16(port) as u64,
        4 => read_port_u32(port) as u64,
        _ => EINVAL,
    }
}

pub fn port_out(port: u64, value: u64, width: u64) -> u64 {
    if !caller_has_port_io_access() {
        return EPERM;
    }
    let port = port as u16;
    match width {
        1 => write_port_u8(port, value as u8),
        2 => write_port_u16(port, value as u16),
        4 => write_port_u32(port, value as u32),
        _ => return EINVAL,
    }
    SUCCESS
}

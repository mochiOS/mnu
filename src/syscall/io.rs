//! I/O関連のシステムコール

use super::types::SUCCESS;
use crate::capability::Capability;
use crate::util::console;
use mnu_abi::status::Error;

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
    let length = match usize::try_from(len) {
        Ok(length) if length <= isize::MAX as usize => length,
        _ => return Error::LimitExceeded.into_raw(),
    };
    if buf_ptr == 0 || buf_ptr.checked_add(len).is_none() {
        return Error::InvalidAddress.into_raw();
    }

    let mut buf = match crate::util::object_snapshot::zeroed_native(length) {
        Ok(buf) => buf,
        Err(error) => return error.into_raw(),
    };
    if let Err(error) = crate::syscall::copy_from_user_native(buf_ptr, &mut buf) {
        return error.into_raw();
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
        return Error::AccessDenied.into_raw();
    }
    let port = match u16::try_from(port) {
        Ok(port) => port,
        Err(_) => return Error::InvalidArgument.into_raw(),
    };
    match width {
        1 => read_port_u8(port) as u64,
        2 => read_port_u16(port) as u64,
        4 => read_port_u32(port) as u64,
        _ => Error::InvalidArgument.into_raw(),
    }
}

pub fn port_out(port: u64, value: u64, width: u64) -> u64 {
    if !caller_has_port_io_access() {
        return Error::AccessDenied.into_raw();
    }
    let port = match u16::try_from(port) {
        Ok(port) => port,
        Err(_) => return Error::InvalidArgument.into_raw(),
    };
    match width {
        1 => write_port_u8(port, value as u8),
        2 => write_port_u16(port, value as u16),
        4 => write_port_u32(port, value as u32),
        _ => return Error::InvalidArgument.into_raw(),
    }
    SUCCESS
}

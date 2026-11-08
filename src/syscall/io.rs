//! I/O関連のシステムコール

use super::types::SUCCESS;
use crate::capability::Capability;
use crate::util::console;
use mnu_abi::status::Error;

fn caller_has_port_io_access(port: u64, width: u64) -> bool {
    use crate::capability::{KernelAuthority, KernelCapability, KernelObjectRef};
    if !matches!(width, 1 | 2 | 4) || port.checked_add(width).is_none_or(|end| end > 65536) {
        return false;
    }
    crate::syscall::security::current_process_id().is_some_and(|pid| {
        crate::task::process_has_kernel_authority(
            pid,
            &KernelAuthority::new(
                KernelCapability::PortIo,
                KernelObjectRef::IoPortRange {
                    base: port,
                    size: width,
                },
            ),
        )
    })
}

/// Writes raw bytes to the kernel's early diagnostic console.
///
/// This is a native debugging mechanism, not a POSIX file descriptor or
/// standard-stream operation. Normal application I/O uses object handles.
pub fn debug_write(buf_ptr: u64, len: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[Capability::KernelDebug]) {
        return Error::AccessDenied.into_raw();
    }
    const MAX_DEBUG_WRITE: u64 = 4096;
    if len > MAX_DEBUG_WRITE {
        return Error::LimitExceeded.into_raw();
    }
    if len == 0 {
        return SUCCESS;
    }
    if buf_ptr == 0 || buf_ptr.checked_add(len).is_none() {
        return Error::InvalidAddress.into_raw();
    }
    let mut bytes = [0u8; 32];
    let mut done = 0usize;
    while done < len as usize {
        let count = bytes.len().min(len as usize - done);
        if let Err(error) =
            crate::syscall::copy_from_user_native(buf_ptr + done as u64, &mut bytes[..count])
        {
            return if done == 0 {
                error.into_raw()
            } else {
                done as u64
            };
        }
        if crate::hypervisor_guest::is_active() {
            let result = crate::hypervisor_guest::invoke(
                mnu_abi::hypervisor::HypercallNumber::ConsoleWrite,
                bytes.as_ptr() as u64,
                count as u64,
                0,
            );
            if result != mnu_abi::hypervisor::HYPERCALL_SUCCESS {
                return if done == 0 {
                    Error::BackingFailure.into_raw()
                } else {
                    done as u64
                };
            }
            done += count;
        } else {
            let written = x86_64::instructions::interrupts::without_interrupts(|| {
                let Some(mut serial) = console::SERIAL.try_lock() else {
                    return 0;
                };
                let mut written = 0;
                for &byte in &bytes[..count] {
                    if !serial.try_send_byte(byte) {
                        break;
                    }
                    written += 1;
                }
                written
            });
            done += written;
            if written != count {
                return if done == 0 {
                    Error::NotReady.into_raw()
                } else {
                    done as u64
                };
            }
        }
        // Neither a UART lock nor a usercopy pin survives a scheduling point.
        if done < len as usize {
            crate::task::yield_now();
        }
    }
    done as u64
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
    if !caller_has_port_io_access(port, width) {
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
    if !caller_has_port_io_access(port, width) {
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

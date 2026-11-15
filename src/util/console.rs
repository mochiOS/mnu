//! シリアルポート出力
//!
//! シリアルポートを使用したシリアル出力

use core::fmt;
#[cfg(target_arch = "x86_64")]
#[path = "../arch/x86_64/console.rs"]
mod serial;
#[cfg(target_arch = "x86_64")]
use serial::lock_serial;
#[cfg(target_arch = "x86_64")]
pub use serial::{SerialPort, SERIAL};

/// シリアルポートを初期化
pub fn init() {
    if crate::hypervisor_guest::is_active() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    lock_serial(|serial| serial.init());
}

/// シリアルポートに文字列を出力（割込み対応）
pub fn print(args: fmt::Arguments) {
    use core::fmt::Write;
    if crate::hypervisor_guest::is_active() {
        let mut writer = HypervisorConsole::new();
        if writer.write_fmt(args).is_ok() {
            let _ = writer.flush();
        }
        return;
    }
    #[cfg(target_arch = "x86_64")]
    lock_serial(|serial| {
        let _ = serial.write_fmt(args);
    });
}

/// Native early console output. ARM requires the boot-provided hypervisor
/// channel; it never assumes a board UART address or fabricates a COM1 device.
pub fn early_write(text: &str) -> Result<(), mnu_abi::status::Error> {
    if crate::hypervisor_guest::is_active() {
        use core::fmt::Write;
        let mut writer = HypervisorConsole::new();
        writer
            .write_str(text)
            .map_err(|_| mnu_abi::status::Error::BackingFailure)?;
        return writer.flush();
    }
    #[cfg(target_arch = "x86_64")]
    return serial::early_write(text);
    #[cfg(target_arch = "aarch64")]
    Err(mnu_abi::status::Error::Unsupported)
}

/// Best-effort direct UART output, after capability admission and usercopy.
/// The hypervisor channel is handled by the shared caller when available.
pub fn try_write_direct(bytes: &[u8]) -> Result<usize, mnu_abi::status::Error> {
    #[cfg(target_arch = "x86_64")]
    return crate::arch::interrupts::without_interrupts(|| {
        let Some(mut serial) = SERIAL.try_lock() else {
            return Err(mnu_abi::status::Error::NotReady);
        };
        let mut written = 0;
        for &byte in bytes {
            if !serial.try_send_byte(byte) {
                break;
            }
            written += 1;
        }
        Ok(written)
    });
    #[cfg(target_arch = "aarch64")]
    {
        let _ = bytes;
        Err(mnu_abi::status::Error::Unsupported)
    }
}

struct HypervisorConsole {
    bytes: [u8; 1024],
    len: usize,
}

impl HypervisorConsole {
    const fn new() -> Self {
        Self {
            bytes: [0; 1024],
            len: 0,
        }
    }

    fn flush(&mut self) -> Result<(), mnu_abi::status::Error> {
        if self.len == 0 {
            return Ok(());
        }
        let mut offset = 0;
        while offset < self.len {
            let address = self.bytes.as_ptr() as u64 + offset as u64;
            let count = (self.len - offset).min(4096 - (address as usize & 4095));
            #[cfg(target_arch = "aarch64")]
            let physical = match crate::arch::memory::current_guest_physical(
                crate::arch::memory::VirtAddr::new(address),
            ) {
                Some(physical) => physical.as_u64(),
                None => return Err(mnu_abi::status::Error::BackingFailure),
            };
            // The existing x86 System Domain diagnostic ABI uses identity
            // addresses. ARM's independently mapped EL1 stack needs AT above.
            #[cfg(target_arch = "x86_64")]
            let physical = address;
            if crate::hypervisor_guest::invoke(
                mnu_abi::hypervisor::HypercallNumber::ConsoleWrite,
                physical,
                count as u64,
                0,
            ) != mnu_abi::hypervisor::HYPERCALL_SUCCESS
            {
                return Err(mnu_abi::status::Error::BackingFailure);
            }
            offset += count;
        }
        self.len = 0;
        Ok(())
    }
}

impl fmt::Write for HypervisorConsole {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut remaining = value.as_bytes();
        while !remaining.is_empty() {
            if self.len == self.bytes.len() {
                self.flush().map_err(|_| fmt::Error)?;
            }
            let count = (self.bytes.len() - self.len).min(remaining.len());
            self.bytes[self.len..self.len + count].copy_from_slice(&remaining[..count]);
            self.len += count;
            remaining = &remaining[count..];
        }
        Ok(())
    }
}

/// シリアル出力マクロ
#[macro_export]
macro_rules! sprint {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            $crate::util::console::print(format_args!($($arg)*))
        }
    };
}

/// 改行付きのシリアル出力マクロ
#[macro_export]
macro_rules! sprintln {
    () => ($crate::sprint!("\n"));
    ($($arg:tt)*) => {
        $crate::sprint!("{}\n", format_args!($($arg)*))
    };
}

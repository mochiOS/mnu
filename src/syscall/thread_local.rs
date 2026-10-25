//! Caller-local CPU context only. No language TLS layout or memory ownership.
use mnu_abi::status::Error;

pub fn set_base(base: u64, reserved: u64) -> u64 {
    if reserved != 0 {
        return Error::InvalidArgument.into_raw();
    }
    // A register value, not a buffer: no mapping is accessed or granted.
    if base != 0 && !super::is_canonical_user_range(base, 0) {
        return Error::InvalidAddress.into_raw();
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let Some(thread) = crate::task::current_thread_id() else {
            return Error::NotReady.into_raw();
        };
        match crate::task::with_thread_mut(thread, |thread| {
            thread.set_fs_base(base);
            // Keep the live register and saved state coherent before a timer
            // can migrate or save this thread, including the next syscall exit.
            unsafe { crate::cpu::write_fs_base(base) };
        }) {
            Some(()) => mnu_abi::SUCCESS,
            None => Error::NotReady.into_raw(),
        }
    })
}

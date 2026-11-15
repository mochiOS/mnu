//! EL1 feature admission and local access protections. No board registers or
//! device discovery are used here. EL2 owns the firmware mitigation conduit.
use core::arch::asm;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

const LOCAL: u8 = 1;
const PAN: u8 = 2;
const RNDR: u8 = 4;
const READY: u8 = 8;
const WORKAROUND_1: u8 = 16;
const WORKAROUND_3: u8 = 32;
static FEATURES: [AtomicU8; crate::percpu::MAX_CPUS] =
    [const { AtomicU8::new(0) }; crate::percpu::MAX_CPUS];

const ARCH_FEATURES: u64 = 0x8000_0001;
const ARCH_WORKAROUND_1: u64 = 0x8000_8000;
const ARCH_WORKAROUND_3: u64 = 0x8000_3fff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitError {
    InvalidContext,
    UnsupportedFloatingPoint,
    UnsupportedByteOrder,
    MissingReadIsolation,
    MissingFirmwareMitigation,
}

fn features() -> u8 {
    FEATURES[crate::percpu::current_cpu_id()].load(Ordering::Acquire)
}

fn pfr0() -> u64 {
    let value;
    // SAFETY: Called only by the admitted EL1 CPU.
    unsafe {
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Admit the base register set before installing vectors or copying userspace
/// memory. This alone does not authorize scheduling or EL0 entry.
pub(crate) fn prepare_local() -> Result<(), InitError> {
    let level: u64;
    let mut control: u64;
    let mmfr1: u64;
    let isar0: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) level, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, sctlr_el1", out(reg) control, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack, preserves_flags));
    }
    if level != 4 || crate::arch::interrupts::are_enabled() || control & 1 == 0 {
        return Err(InitError::InvalidContext);
    }
    if control & ((1 << 25) | (1 << 24)) != 0 {
        return Err(InitError::UnsupportedByteOrder);
    }
    let pfr = pfr0();
    if (pfr >> 16) & 15 > 1 || (pfr >> 20) & 15 > 1 {
        return Err(InitError::UnsupportedFloatingPoint);
    }
    let pan = matches!((mmfr1 >> 20) & 15, 1..=3);
    let mut access: u64;
    // SAFETY: Only the preserved FP/AdvSIMD register set is enabled. SVE/SME
    // remain trapped because their state is not part of the thread ABI.
    unsafe {
        asm!("mrs {}, cpacr_el1", out(reg) access, options(nomem, nostack, preserves_flags));
        access = (access & !((3 << 16) | (3 << 24))) | (3 << 20);
        asm!("msr cpacr_el1, {}", "isb", in(reg) access, options(nostack, preserves_flags));
    }
    control |= (1 << 3) | (1 << 4); // SP alignment in EL1 and EL0.
    control &= !((1 << 9) | (1 << 14) | (1 << 15) | (1 << 26));
    if pan {
        control &= !(1 << 23); // SPAN=0 restores PAN on every exception entry.
    }
    unsafe {
        asm!("msr sctlr_el1, {}", "isb", in(reg) control, options(nostack, preserves_flags));
    }
    let flags = LOCAL | if pan { PAN } else { 0 } | if isar0 >> 60 == 1 { RNDR } else { 0 };
    FEATURES[crate::percpu::current_cpu_id()].store(flags, Ordering::Release);
    if pan {
        unsafe { set_pan(true) };
    }
    Ok(())
}

/// The SMCCC response is signed 32-bit: only success (0) and explicitly
/// unaffected (1) are admissible. Unknown/unsupported is never a no-op barrier.
pub(crate) fn mitigation_calls(first: u64, third: u64) -> Option<u8> {
    fn required(status: u64, bit: u8) -> Option<u8> {
        match status as u32 as i32 {
            0 => Some(bit),
            1 => Some(0),
            _ => None,
        }
    }
    Some(required(first, WORKAROUND_1)? | required(third, WORKAROUND_3)?)
}

#[cfg(not(mnu_arch_probe))]
pub fn init() {
    if let Err(error) = initialize() {
        crate::error!("ARM CPU admission failed: {:?}", error);
        crate::arch::halt();
    }
}

#[cfg(not(mnu_arch_probe))]
fn initialize() -> Result<(), InitError> {
    prepare_local()?;
    // TTBR1 remains mapped in EL0. CPUs without architectural read isolation
    // need a separate KPTI implementation; do not pretend PXN alone fixes it.
    if (pfr0() >> 60) & 15 != 1 {
        return Err(InitError::MissingReadIsolation);
    }
    if !crate::hypervisor_guest::is_active() {
        return Err(InitError::MissingFirmwareMitigation);
    }
    let first = smccc(ARCH_FEATURES, ARCH_WORKAROUND_1);
    let third = smccc(ARCH_FEATURES, ARCH_WORKAROUND_3);
    let calls = mitigation_calls(first, third).ok_or(InitError::MissingFirmwareMitigation)?;
    FEATURES[crate::percpu::current_cpu_id()].fetch_or(READY | calls, Ordering::AcqRel);
    branch_predictor_barrier();
    Ok(())
}

fn smccc(function: u64, argument: u64) -> u64 {
    // SAFETY: The production initializer verifies the native EL2 transport;
    // only architected SMCCC feature/mitigation calls reach this helper.
    unsafe {
        crate::arch::hypercall::invoke(
            crate::arch::hypercall::Transport::ArmEl2,
            function,
            [argument, 0, 0],
        )
        .unwrap_or(u64::MAX)
    }
}

pub fn hw_random_u64() -> Option<u64> {
    if features() & RNDR == 0 {
        return None;
    }
    for _ in 0..10 {
        let value;
        let ok: u64;
        // SAFETY: RNDR was admitted on this CPU. Read the success condition,
        // not its zeroed failure value; no flag-preservation claim is made.
        unsafe {
            asm!("mrs {value}, S3_3_C2_C4_0", "cset {ok}, ne",
                value = out(reg) value, ok = out(reg) ok, options(nomem, nostack));
        }
        if ok != 0 {
            return Some(value);
        }
    }
    None
}

pub fn is_smap_enabled() -> bool {
    if features() & PAN == 0 {
        return false;
    }
    let value: u64;
    unsafe {
        asm!("mrs {}, S3_0_C4_C2_3", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value & (1 << 22) != 0
}

unsafe fn set_pan(enabled: bool) {
    // The encodings keep this module usable with a baseline Armv8 assembler.
    // Execution is guarded by this CPU's FEAT_PAN, never just the build target.
    if enabled {
        unsafe { asm!(".inst 0xd500419f", options(nostack, preserves_flags)) };
    } else {
        unsafe { asm!(".inst 0xd500409f", options(nostack, preserves_flags)) };
    }
}

/// # Safety
/// Exclude scheduling and restore the previous access scope before resuming
/// interrupts. Prefer SmapSmepGuard for bounded userspace data copies.
pub unsafe fn disable_smap() {
    if features() & PAN != 0 {
        unsafe { set_pan(false) };
    }
}

/// # Safety
/// No user-memory copy may remain active on this CPU.
pub unsafe fn enable_smap() {
    if features() & PAN != 0 {
        unsafe { set_pan(true) };
    }
}

/// CPU-local user-data access scope. Privileged execute-never remains intact.
/// Do not schedule/yield while this guard lives. Nested scopes restore their
/// exact PAN/IRQ state; an enabled timer cannot migrate the open access scope.
pub struct SmapSmepGuard {
    pan: bool,
    interrupts: bool,
    owner: u64,
    _local: PhantomData<*mut ()>,
}

impl SmapSmepGuard {
    pub fn new() -> Self {
        let interrupts = crate::arch::interrupts::are_enabled();
        crate::arch::interrupts::disable();
        let guard = Self {
            pan: is_smap_enabled(),
            interrupts,
            owner: crate::percpu::hardware_id(),
            _local: PhantomData,
        };
        unsafe { disable_smap() };
        guard
    }
}

impl Drop for SmapSmepGuard {
    fn drop(&mut self) {
        if crate::arch::interrupts::are_enabled() || self.owner != crate::percpu::hardware_id() {
            crate::arch::halt();
        }
        if features() & PAN != 0 {
            unsafe { set_pan(self.pan) };
        }
        if self.interrupts {
            crate::arch::interrupts::enable();
        }
    }
}

pub fn speculation_barrier() {
    // This stops speculation; it is deliberately not used as a substitute for
    // flushing predictor/history state at a protection-domain transition.
    unsafe { asm!("dsb nsh", "isb", options(nostack, preserves_flags)) };
}

pub fn branch_predictor_barrier() {
    let flags = features();
    if flags & READY == 0 || crate::arch::interrupts::are_enabled() {
        crate::arch::halt();
    }
    if flags & WORKAROUND_1 != 0 {
        let _ = smccc(ARCH_WORKAROUND_1, 0);
    }
    if flags & WORKAROUND_3 != 0 {
        let _ = smccc(ARCH_WORKAROUND_3, 0);
    }
    speculation_barrier();
}

pub fn reassert_runtime_hardening() {
    if features() & READY == 0 {
        crate::arch::halt();
    }
    unsafe { enable_smap() };
    let mut control: u64;
    // The final VM mappings have read-only executable text. Never call this
    // during an identity bootstrap with writable executable mappings.
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) control, options(nomem, nostack, preserves_flags));
        control |= (1 << 19) | (1 << 3) | (1 << 4); // WXN, SA, SA0.
        control &= !((1 << 9) | (1 << 14) | (1 << 15) | (1 << 26));
        if features() & PAN != 0 {
            control &= !(1 << 23);
        }
        asm!("msr sctlr_el1, {}", "isb", in(reg) control, options(nostack, preserves_flags));
    }
}

#[cfg(not(mnu_arch_probe))]
pub use mnu_time_core::UtcDateTime as RtcDateTime;

#[cfg(not(mnu_arch_probe))]
pub fn rtc_utc() -> Option<RtcDateTime> {
    // ARM has no architectural civil-time RTC. Platform time is supplied by
    // the userland driver/service rather than probing an invented board port.
    None
}

#[cfg(not(mnu_arch_probe))]
#[path = "boot_entropy.rs"]
mod entropy;
#[cfg(not(mnu_arch_probe))]
pub use entropy::boot_entropy_u64;

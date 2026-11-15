//! Banked architected virtual timer. EL2 assigns its PPI and counter offset;
//! GIC discovery/routing and shared scheduler time are separate responsibilities.
use core::{arch::asm, marker::PhantomData};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidFrequency,
    InterruptsEnabled,
    WrongCpu,
    NotPending,
}

/// Counter arithmetic shared by every vCPU. It measures time from one retained
/// origin, so adding CPUs or missing interrupts does not change the clock rate.
#[derive(Clone, Copy)]
pub struct Clock {
    origin: u64,
    frequency: u64,
    rate: u64,
}

impl Clock {
    pub fn new(origin: u64, frequency: u64, rate: u64) -> Result<Self, Error> {
        if frequency == 0 || frequency > u64::from(u32::MAX) || rate == 0 || rate > frequency {
            return Err(Error::InvalidFrequency);
        }
        Ok(Self {
            origin,
            frequency,
            rate,
        })
    }

    pub fn ticks(self, now: u64) -> u64 {
        // A counter reset/backwards jump is outside the admitted clock epoch.
        let elapsed = now.wrapping_sub(self.origin);
        if elapsed > i64::MAX as u64 {
            return 0;
        }
        ((u128::from(elapsed) * u128::from(self.rate)) / u128::from(self.frequency))
            .min(u128::from(u64::MAX)) as u64
    }
}

/// A register access token for this admitted CPU, never transferable to another.
pub struct LocalTimer {
    period: u64,
    owner: u64,
    _local: PhantomData<*mut ()>,
}

impl LocalTimer {
    pub fn new(rate: u64) -> Result<Self, Error> {
        if crate::arch::interrupts::are_enabled() {
            return Err(Error::InterruptsEnabled);
        }
        let frequency = super::counter::frequency_hz();
        Clock::new(0, frequency, rate)?;
        Ok(Self {
            period: frequency / rate,
            owner: crate::percpu::hardware_id(),
            _local: PhantomData,
        })
    }

    fn check_cpu(&self) -> Result<(), Error> {
        if self.owner != crate::percpu::hardware_id() {
            return Err(Error::WrongCpu);
        }
        if crate::arch::interrupts::are_enabled() {
            return Err(Error::InterruptsEnabled);
        }
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), Error> {
        self.check_cpu()?;
        let deadline = super::counter::timestamp().wrapping_add(self.period);
        // SAFETY: EL1 owns this banked virtual timer and runs under the EL2
        // contract that permits counter/timer access. IRQ routing is external.
        unsafe {
            asm!("msr cntv_ctl_el0, xzr", "isb", "msr cntv_cval_el0, {}",
                "msr cntv_ctl_el0, {}", "isb",
                in(reg) deadline, in(reg) 1u64, options(nostack, preserves_flags));
        }
        Ok(())
    }

    /// Clear the pending level and rearm from the previous deadline. Delayed
    /// service skips whole periods; handler latency does not accumulate drift.
    pub fn handle(&mut self) -> Result<u64, Error> {
        self.check_cpu()?;
        let control: u64;
        let deadline: u64;
        unsafe {
            asm!("mrs {}, cntv_ctl_el0", out(reg) control, options(nomem, nostack, preserves_flags));
            asm!("mrs {}, cntv_cval_el0", out(reg) deadline, options(nomem, nostack, preserves_flags));
        }
        let now = super::counter::timestamp();
        let elapsed = now.wrapping_sub(deadline);
        if control & 7 != 5 || elapsed > i64::MAX as u64 {
            return Err(Error::NotPending);
        }
        let periods = elapsed / self.period + 1;
        let next = deadline.wrapping_add(periods * self.period);
        unsafe {
            asm!("msr cntv_cval_el0, {}", "isb", in(reg) next, options(nostack, preserves_flags));
        }
        Ok(now)
    }

    pub fn stop(&mut self) -> Result<(), Error> {
        self.check_cpu()?;
        unsafe {
            asm!(
                "msr cntv_ctl_el0, xzr",
                "isb",
                options(nostack, preserves_flags)
            )
        };
        Ok(())
    }
}

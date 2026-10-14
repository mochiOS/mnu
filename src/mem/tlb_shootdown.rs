//! CPU transport for full translation invalidation. No process-table or
//! allocator locks are taken while servicing a request.
use super::tlb_rendezvous::Rendezvous;
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const VECTOR: u8 = 49;
static LEDGER: Rendezvous<{ crate::percpu::MAX_CPUS }> = Rendezvous::new();
static ONLINE: AtomicU64 = AtomicU64::new(0);

/// Reuse the membership established before CPUs enter user context; discovery
/// must not count firmware entries whose processors failed to come online.
pub(crate) fn online_cpu_count() -> u32 {
    ONLINE.load(Ordering::Acquire).count_ones()
}

/// After IDT/APIC initialization, before entering user context. New CPUs have
/// no retained user translations; subsequent user entry loads CR3. Hot-unplug
/// must retire pending requests before removing a CPU if implemented later.
pub(crate) fn mark_current_cpu_online() {
    service_pending();
    ONLINE.fetch_or(1u64 << crate::percpu::current_cpu_id(), Ordering::Release);
}

/// Called with interrupts disabled by the IPI handler or kernel lock waiter.
pub(crate) fn service_pending() {
    let cpu = crate::percpu::current_cpu_id();
    let _ = LEDGER.service(cpu, || {
        super::paging::flush_all_translations_local();
        Ok::<_, ()>(())
    });
}

/// Page-table edits precede this call; retain old frames until it succeeds.
/// Cooperating lock waiters break the IF=0/process-lock/IPI cycle. Full flushes
/// can later target address-space residency without weakening completion.
pub(crate) fn invalidate_all() -> Result<(), ()> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let targets = ONLINE.load(Ordering::Acquire);
        let publication = LEDGER.publish(targets).map_err(|_| ())?;
        let current = crate::percpu::current_cpu_id();
        service_pending();
        for cpu in 0..crate::percpu::MAX_CPUS {
            if cpu != current
                && targets & (1u64 << cpu) != 0
                && !crate::smp::send_fixed_ipi(cpu as u32, VECTOR)
            {
                return Err(());
            }
        }
        while !publication.complete() {
            service_pending();
            core::hint::spin_loop();
        }
        Ok(())
    })
}

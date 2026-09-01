use core::arch::{asm, x86_64::__cpuid_count};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

#[cfg(feature = "performance-instrumentation")]
use core::sync::atomic::AtomicU64;
pub use mnu_abi::performance::{
    AllocationSubsystem, BootMilestone, CounterMetric, GaugeMetric, HeapAllocationSizeClass,
    LatencyMetric,
};
#[cfg(feature = "performance-instrumentation")]
use mnu_metrics::{
    AtomicGauge, AtomicHistogram, GaugeSnapshot as MetricGaugeSnapshot, HistogramSnapshot,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockSource {
    Unavailable,
    MbootVirtual,
    CpuidCrystal,
}

impl ClockSource {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::MbootVirtual,
            2 => Self::CpuidCrystal,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockInfo {
    pub invariant_tsc: bool,
    pub rdtscp: bool,
    pub frequency_khz: u32,
    pub source: ClockSource,
}

static CLOCK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static INVARIANT_TSC: AtomicBool = AtomicBool::new(false);
static RDTSCP: AtomicBool = AtomicBool::new(false);
static TSC_FREQUENCY_KHZ: AtomicU32 = AtomicU32::new(0);
static TSC_FREQUENCY_SOURCE: AtomicU8 = AtomicU8::new(ClockSource::Unavailable as u8);

#[cfg(feature = "performance-instrumentation")]
static LATENCIES: [[AtomicHistogram; LatencyMetric::COUNT]; crate::percpu::MAX_CPUS] =
    [const { [const { AtomicHistogram::new() }; LatencyMetric::COUNT] }; crate::percpu::MAX_CPUS];
#[cfg(feature = "performance-instrumentation")]
static COUNTERS: [AtomicU64; CounterMetric::COUNT] =
    [const { AtomicU64::new(0) }; CounterMetric::COUNT];
#[cfg(feature = "performance-instrumentation")]
static GAUGES: [AtomicGauge; GaugeMetric::COUNT] =
    [const { AtomicGauge::new() }; GaugeMetric::COUNT];
#[cfg(feature = "performance-instrumentation")]
static BOOT_MILESTONES: [AtomicU64; BootMilestone::COUNT] =
    [const { AtomicU64::new(0) }; BootMilestone::COUNT];
#[cfg(feature = "performance-instrumentation")]
static HEAP_ALLOCATIONS_BY_SIZE: [AtomicU64; HeapAllocationSizeClass::COUNT] =
    [const { AtomicU64::new(0) }; HeapAllocationSizeClass::COUNT];
#[cfg(feature = "performance-instrumentation")]
static HEAP_ALLOCATIONS_BY_CPU: [AtomicU64; mnu_abi::performance::PERFORMANCE_CPU_SLOTS] =
    [const { AtomicU64::new(0) }; mnu_abi::performance::PERFORMANCE_CPU_SLOTS];
#[cfg(feature = "performance-instrumentation")]
static HEAP_ALLOCATIONS_BY_SUBSYSTEM: [AtomicU64; AllocationSubsystem::COUNT] =
    [const { AtomicU64::new(0) }; AllocationSubsystem::COUNT];
#[cfg(feature = "performance-instrumentation")]
static HEAP_INTERNAL_FRAGMENTATION: AtomicGauge = AtomicGauge::new();

#[cfg(feature = "performance-instrumentation")]
const ALLOCATION_THREAD_SLOTS: usize = 64;
#[cfg(feature = "performance-instrumentation")]
const ALLOCATION_CONTEXT_SLOTS: usize =
    ALLOCATION_THREAD_SLOTS + mnu_abi::performance::PERFORMANCE_CPU_SLOTS;
#[cfg(feature = "performance-instrumentation")]
static ALLOCATION_CONTEXTS: [AtomicU8; ALLOCATION_CONTEXT_SLOTS] =
    [const { AtomicU8::new(AllocationSubsystem::Other as u8) }; ALLOCATION_CONTEXT_SLOTS];

pub struct AllocationScope {
    #[cfg(feature = "performance-instrumentation")]
    context_index: usize,
    #[cfg(feature = "performance-instrumentation")]
    previous: u8,
}

impl AllocationScope {
    #[inline]
    pub fn enter(subsystem: AllocationSubsystem) -> Self {
        #[cfg(feature = "performance-instrumentation")]
        {
            let context_index = allocation_context_index();
            let previous =
                ALLOCATION_CONTEXTS[context_index].swap(subsystem as u8, Ordering::Relaxed);
            return Self {
                context_index,
                previous,
            };
        }

        #[cfg(not(feature = "performance-instrumentation"))]
        {
            let _ = subsystem;
            Self {}
        }
    }
}

impl Drop for AllocationScope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "performance-instrumentation")]
        ALLOCATION_CONTEXTS[self.context_index].store(self.previous, Ordering::Relaxed);
    }
}

#[cfg(feature = "performance-instrumentation")]
fn allocation_context_index() -> usize {
    crate::percpu::current_thread_slot()
        .filter(|slot| *slot < ALLOCATION_THREAD_SLOTS)
        .unwrap_or_else(|| ALLOCATION_THREAD_SLOTS + crate::percpu::current_cpu_id())
}

#[cfg(feature = "performance-instrumentation")]
fn current_allocation_subsystem() -> AllocationSubsystem {
    match ALLOCATION_CONTEXTS[allocation_context_index()].load(Ordering::Relaxed) {
        1 => AllocationSubsystem::Scheduler,
        2 => AllocationSubsystem::Ipc,
        3 => AllocationSubsystem::Vfs,
        4 => AllocationSubsystem::PageFault,
        5 => AllocationSubsystem::NetworkReceive,
        6 => AllocationSubsystem::NetworkTransmit,
        7 => AllocationSubsystem::BlockIo,
        8 => AllocationSubsystem::ProcessCreation,
        9 => AllocationSubsystem::ThreadCreation,
        10 => AllocationSubsystem::Syscall,
        _ => AllocationSubsystem::Other,
    }
}

#[inline]
pub fn record_heap_allocation(user_bytes: usize, reserved_bytes: usize) {
    #[cfg(feature = "performance-instrumentation")]
    {
        let size_class = HeapAllocationSizeClass::for_size(user_bytes);
        HEAP_ALLOCATIONS_BY_SIZE[size_class as usize].fetch_add(1, Ordering::Relaxed);

        let cpu = crate::percpu::current_cpu_id();
        HEAP_ALLOCATIONS_BY_CPU[cpu].fetch_add(1, Ordering::Relaxed);

        let subsystem = current_allocation_subsystem();
        HEAP_ALLOCATIONS_BY_SUBSYSTEM[subsystem as usize].fetch_add(1, Ordering::Relaxed);
        HEAP_INTERNAL_FRAGMENTATION.add(reserved_bytes.saturating_sub(user_bytes) as u64);
    }

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (user_bytes, reserved_bytes);
}

#[inline]
pub fn record_heap_deallocation(user_bytes: usize, reserved_bytes: usize) {
    #[cfg(feature = "performance-instrumentation")]
    HEAP_INTERNAL_FRAGMENTATION.subtract(reserved_bytes.saturating_sub(user_bytes) as u64);

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (user_bytes, reserved_bytes);
}

pub fn initialize_clock() -> ClockInfo {
    let maximum_extended_leaf = cpuid(0x8000_0000, 0).eax;
    let rdtscp = maximum_extended_leaf >= 0x8000_0001 && cpuid(0x8000_0001, 0).edx & (1 << 27) != 0;
    let invariant_tsc =
        maximum_extended_leaf >= 0x8000_0007 && cpuid(0x8000_0007, 0).edx & (1 << 8) != 0;
    let (frequency_khz, source) = tsc_frequency();

    RDTSCP.store(rdtscp, Ordering::Relaxed);
    INVARIANT_TSC.store(invariant_tsc, Ordering::Relaxed);
    TSC_FREQUENCY_KHZ.store(frequency_khz, Ordering::Relaxed);
    TSC_FREQUENCY_SOURCE.store(source as u8, Ordering::Relaxed);
    CLOCK_INITIALIZED.store(true, Ordering::Release);

    ClockInfo {
        invariant_tsc,
        rdtscp,
        frequency_khz,
        source,
    }
}

pub fn clock_info() -> ClockInfo {
    ClockInfo {
        invariant_tsc: INVARIANT_TSC.load(Ordering::Relaxed),
        rdtscp: RDTSCP.load(Ordering::Relaxed),
        frequency_khz: TSC_FREQUENCY_KHZ.load(Ordering::Relaxed),
        source: ClockSource::from_raw(TSC_FREQUENCY_SOURCE.load(Ordering::Relaxed)),
    }
}

#[inline]
pub fn timestamp() -> u64 {
    if CLOCK_INITIALIZED.load(Ordering::Acquire) && RDTSCP.load(Ordering::Relaxed) {
        read_rdtscp()
    } else {
        read_ordered_tsc()
    }
}

#[inline]
pub fn elapsed_cycles(start: u64) -> u64 {
    timestamp().saturating_sub(start)
}

pub fn cycles_to_nanoseconds(cycles: u64) -> Option<u64> {
    let frequency_khz = u128::from(TSC_FREQUENCY_KHZ.load(Ordering::Relaxed));
    if frequency_khz == 0 {
        return None;
    }
    let nanoseconds = u128::from(cycles).saturating_mul(1_000_000) / frequency_khz;
    u64::try_from(nanoseconds).ok()
}

#[inline]
pub fn record_latency(metric: LatencyMetric, start: u64) {
    #[cfg(feature = "performance-instrumentation")]
    LATENCIES[crate::percpu::current_cpu_id()][metric as usize].record(elapsed_cycles(start));

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (metric, start);
}

#[cfg(feature = "performance-instrumentation")]
pub fn latency_snapshot(metric: LatencyMetric) -> HistogramSnapshot {
    merged_latency(metric as usize)
}

#[inline]
pub fn increment(metric: CounterMetric, value: u64) {
    #[cfg(feature = "performance-instrumentation")]
    {
        let counter = &COUNTERS[metric as usize];
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        });
    }

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (metric, value);
}

#[cfg(feature = "performance-instrumentation")]
pub fn counter(metric: CounterMetric) -> u64 {
    COUNTERS[metric as usize].load(Ordering::Relaxed)
}

#[inline]
pub fn gauge_add(metric: GaugeMetric, value: u64) {
    #[cfg(feature = "performance-instrumentation")]
    GAUGES[metric as usize].add(value);

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (metric, value);
}

#[inline]
pub fn gauge_subtract(metric: GaugeMetric, value: u64) {
    #[cfg(feature = "performance-instrumentation")]
    GAUGES[metric as usize].subtract(value);

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (metric, value);
}

#[cfg(feature = "performance-instrumentation")]
pub fn gauge_snapshot(metric: GaugeMetric) -> MetricGaugeSnapshot {
    GAUGES[metric as usize].snapshot()
}

#[inline]
pub fn mark_boot(milestone: BootMilestone) {
    #[cfg(feature = "performance-instrumentation")]
    {
        let timestamp = timestamp().max(1);
        let _ = BOOT_MILESTONES[milestone as usize].compare_exchange(
            0,
            timestamp,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = milestone;
}

#[cfg(feature = "performance-instrumentation")]
pub fn boot_milestone(milestone: BootMilestone) -> Option<u64> {
    let timestamp = BOOT_MILESTONES[milestone as usize].load(Ordering::Relaxed);
    (timestamp != 0).then_some(timestamp)
}

#[cfg(feature = "performance-instrumentation")]
pub fn snapshot() -> mnu_abi::performance::KernelPerformanceSnapshot {
    use mnu_abi::performance::{
        GaugeSnapshot, KernelPerformanceSnapshot, PERFORMANCE_FLAG_INSTRUMENTED,
        PERFORMANCE_FLAG_INVARIANT_TSC, PERFORMANCE_FLAG_RDTSCP, PERFORMANCE_FLAG_WEAK_SNAPSHOT,
        PERFORMANCE_SNAPSHOT_VERSION,
    };

    let clock = clock_info();
    let mut flags = PERFORMANCE_FLAG_INSTRUMENTED | PERFORMANCE_FLAG_WEAK_SNAPSHOT;
    if clock.invariant_tsc {
        flags |= PERFORMANCE_FLAG_INVARIANT_TSC;
    }
    if clock.rdtscp {
        flags |= PERFORMANCE_FLAG_RDTSCP;
    }

    let gauges: [GaugeSnapshot; GaugeMetric::COUNT] = core::array::from_fn(|index| {
        let snapshot = GAUGES[index].snapshot();
        GaugeSnapshot {
            current: snapshot.current,
            peak: snapshot.peak,
        }
    });
    let frames_in_use = gauges[GaugeMetric::FramesInUse as usize].current;
    let frames_quarantined = gauges[GaugeMetric::FramesQuarantined as usize].current;
    let usable_frames = crate::mem::frame::get_memory_info()
        .map(|(_, frames)| frames as u64)
        .unwrap_or(0);

    KernelPerformanceSnapshot {
        version: PERFORMANCE_SNAPSHOT_VERSION,
        size: core::mem::size_of::<KernelPerformanceSnapshot>() as u32,
        flags,
        tsc_frequency_khz: u64::from(clock.frequency_khz),
        clock_source: clock.source as u32,
        kernel_stack_high_water_bytes: crate::task::kernel_stack_high_water_bytes(),
        usable_frames,
        free_frames: usable_frames.saturating_sub(frames_in_use.saturating_add(frames_quarantined)),
        heap_capacity_bytes: crate::mem::allocator::HEAP_SIZE as u64,
        counters: core::array::from_fn(|index| COUNTERS[index].load(Ordering::Relaxed)),
        gauges,
        latencies: core::array::from_fn(|index| distribution_snapshot(merged_latency(index))),
        boot_timestamps: core::array::from_fn(|index| {
            BOOT_MILESTONES[index].load(Ordering::Relaxed)
        }),
        heap_committed_bytes: crate::mem::allocator::heap_committed_bytes() as u64,
        heap_internal_fragmentation: {
            let snapshot = HEAP_INTERNAL_FRAGMENTATION.snapshot();
            GaugeSnapshot {
                current: snapshot.current,
                peak: snapshot.peak,
            }
        },
        heap_allocations_by_size: core::array::from_fn(|index| {
            HEAP_ALLOCATIONS_BY_SIZE[index].load(Ordering::Relaxed)
        }),
        heap_allocations_by_cpu: core::array::from_fn(|index| {
            HEAP_ALLOCATIONS_BY_CPU[index].load(Ordering::Relaxed)
        }),
        heap_allocations_by_subsystem: core::array::from_fn(|index| {
            HEAP_ALLOCATIONS_BY_SUBSYSTEM[index].load(Ordering::Relaxed)
        }),
    }
}

#[cfg(feature = "performance-instrumentation")]
fn merged_latency(metric_index: usize) -> HistogramSnapshot {
    let mut merged = HistogramSnapshot::empty();
    for cpu in &LATENCIES {
        merged.merge(&cpu[metric_index].snapshot());
    }
    merged
}

#[cfg(feature = "performance-instrumentation")]
fn distribution_snapshot(
    snapshot: HistogramSnapshot,
) -> mnu_abi::performance::DistributionSnapshot {
    mnu_abi::performance::DistributionSnapshot {
        count: snapshot.count,
        sum_cycles: snapshot.sum,
        max_cycles: snapshot.max,
        p50_cycles: snapshot.percentile(50, 100).unwrap_or(0),
        p95_cycles: snapshot.percentile(95, 100).unwrap_or(0),
        p99_cycles: snapshot.percentile(99, 100).unwrap_or(0),
    }
}

fn tsc_frequency() -> (u32, ClockSource) {
    let hypervisor_frequency = crate::hypervisor_guest::tsc_frequency_khz();
    if hypervisor_frequency != 0 {
        return (hypervisor_frequency, ClockSource::MbootVirtual);
    }

    let maximum_basic_leaf = cpuid(0, 0).eax;
    if maximum_basic_leaf >= 0x15 {
        let ratio = cpuid(0x15, 0);
        if ratio.eax != 0 && ratio.ebx != 0 && ratio.ecx != 0 {
            let frequency_hz =
                u64::from(ratio.ecx).saturating_mul(u64::from(ratio.ebx)) / u64::from(ratio.eax);
            if let Ok(frequency_khz) = u32::try_from(frequency_hz / 1_000) {
                return (frequency_khz, ClockSource::CpuidCrystal);
            }
        }
    }

    (0, ClockSource::Unavailable)
}

#[derive(Clone, Copy)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let result = __cpuid_count(leaf, subleaf);
    CpuidResult {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

#[inline]
fn read_ordered_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[inline]
fn read_rdtscp() -> u64 {
    let low: u32;
    let high: u32;
    let auxiliary: u32;
    unsafe {
        asm!(
            "rdtscp",
            "lfence",
            out("eax") low,
            out("edx") high,
            out("ecx") auxiliary,
            options(nomem, nostack, preserves_flags),
        );
    }
    let _ = auxiliary;
    (u64::from(high) << 32) | u64::from(low)
}

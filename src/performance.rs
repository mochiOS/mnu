use core::arch::{asm, x86_64::__cpuid_count};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

#[cfg(feature = "performance-instrumentation")]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "performance-instrumentation")]
use mnu_metrics::{AtomicGauge, AtomicHistogram, GaugeSnapshot, HistogramSnapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum LatencyMetric {
    IpcSmallOneWay,
    IpcSmallRoundTrip,
    IpcFourKilobytes,
    IpcLockWait,
    IpcWakeup,
    ContextSwitch,
    SchedulerRunQueue,
    SchedulerWakeup,
    VfsPathLookup,
    VfsOpen,
    VfsRead,
    VfsWrite,
    VfsClose,
    VfsStat,
    ExecParse,
    ExecLoad,
    ExecRelocate,
    ExecEntry,
}

#[cfg(feature = "performance-instrumentation")]
impl LatencyMetric {
    const COUNT: usize = Self::ExecEntry as usize + 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum CounterMetric {
    HeapAllocations,
    HeapAllocationBytes,
    HeapFrees,
    HeapFreedBytes,
    HeapAllocationFailures,
    FrameAllocations,
    FrameFrees,
    IpcBytesCopied,
    IpcSendAllocations,
    IpcReceiveAllocations,
    TimerInterrupts,
    PageFaults,
    ExecutableBytesRead,
}

#[cfg(feature = "performance-instrumentation")]
impl CounterMetric {
    const COUNT: usize = Self::ExecutableBytesRead as usize + 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum GaugeMetric {
    HeapLiveBytes,
    HeapReservedBytes,
    HeapQuarantinedBytes,
    FramesInUse,
    FramesQuarantined,
}

#[cfg(feature = "performance-instrumentation")]
impl GaugeMetric {
    const COUNT: usize = Self::FramesQuarantined as usize + 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum BootMilestone {
    MnuEntry,
    EarlyMemoryReady,
    PageAllocatorReady,
    BspReady,
    ApReady,
    SchedulerStarted,
    FilesystemMounted,
    SystemServicesStarted,
    CompositorStarted,
    BinderStarted,
    BinderFirstFrame,
    Idle,
}

#[cfg(feature = "performance-instrumentation")]
impl BootMilestone {
    const COUNT: usize = Self::Idle as usize + 1;
}

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
static LATENCIES: [AtomicHistogram; LatencyMetric::COUNT] =
    [const { AtomicHistogram::new() }; LatencyMetric::COUNT];
#[cfg(feature = "performance-instrumentation")]
static COUNTERS: [AtomicU64; CounterMetric::COUNT] =
    [const { AtomicU64::new(0) }; CounterMetric::COUNT];
#[cfg(feature = "performance-instrumentation")]
static GAUGES: [AtomicGauge; GaugeMetric::COUNT] =
    [const { AtomicGauge::new() }; GaugeMetric::COUNT];
#[cfg(feature = "performance-instrumentation")]
static BOOT_MILESTONES: [AtomicU64; BootMilestone::COUNT] =
    [const { AtomicU64::new(0) }; BootMilestone::COUNT];

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
    LATENCIES[metric as usize].record(elapsed_cycles(start));

    #[cfg(not(feature = "performance-instrumentation"))]
    let _ = (metric, start);
}

#[cfg(feature = "performance-instrumentation")]
pub fn latency_snapshot(metric: LatencyMetric) -> HistogramSnapshot {
    LATENCIES[metric as usize].snapshot()
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
pub fn gauge_snapshot(metric: GaugeMetric) -> GaugeSnapshot {
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

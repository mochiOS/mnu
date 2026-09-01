pub const PERFORMANCE_SNAPSHOT_VERSION: u32 = 1;

pub const PERFORMANCE_FLAG_INSTRUMENTED: u64 = 1 << 0;
pub const PERFORMANCE_FLAG_INVARIANT_TSC: u64 = 1 << 1;
pub const PERFORMANCE_FLAG_RDTSCP: u64 = 1 << 2;
pub const PERFORMANCE_FLAG_WEAK_SNAPSHOT: u64 = 1 << 3;

pub const CLOCK_SOURCE_UNAVAILABLE: u32 = 0;
pub const CLOCK_SOURCE_MBOOT: u32 = 1;
pub const CLOCK_SOURCE_CPUID_CRYSTAL: u32 = 2;

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

impl LatencyMetric {
    pub const COUNT: usize = Self::ExecEntry as usize + 1;
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

impl CounterMetric {
    pub const COUNT: usize = Self::ExecutableBytesRead as usize + 1;
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

impl GaugeMetric {
    pub const COUNT: usize = Self::FramesQuarantined as usize + 1;
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

impl BootMilestone {
    pub const COUNT: usize = Self::Idle as usize + 1;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributionSnapshot {
    pub count: u64,
    pub sum_cycles: u64,
    pub max_cycles: u64,
    pub p50_cycles: u64,
    pub p95_cycles: u64,
    pub p99_cycles: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GaugeSnapshot {
    pub current: u64,
    pub peak: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelPerformanceSnapshot {
    pub version: u32,
    pub size: u32,
    pub flags: u64,
    pub tsc_frequency_khz: u64,
    pub clock_source: u32,
    /// 計測buildで観測した、単一kernel stackの最大使用量。
    pub kernel_stack_high_water_bytes: u32,
    pub usable_frames: u64,
    pub free_frames: u64,
    pub heap_capacity_bytes: u64,
    pub counters: [u64; CounterMetric::COUNT],
    pub gauges: [GaugeSnapshot; GaugeMetric::COUNT],
    pub latencies: [DistributionSnapshot; LatencyMetric::COUNT],
    pub boot_timestamps: [u64; BootMilestone::COUNT],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<DistributionSnapshot>(), 48);
        assert_eq!(core::mem::size_of::<GaugeSnapshot>(), 16);
        assert_eq!(core::mem::size_of::<KernelPerformanceSnapshot>(), 1_200);
        assert_eq!(core::mem::align_of::<KernelPerformanceSnapshot>(), 8);
    }
}

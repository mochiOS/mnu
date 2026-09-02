pub const PERFORMANCE_SNAPSHOT_VERSION: u32 = 7;
pub const PERFORMANCE_SNAPSHOT_V1_SIZE: usize = 1_200;
pub const PERFORMANCE_SNAPSHOT_V2_SIZE: usize = 1_896;
pub const PERFORMANCE_SNAPSHOT_V3_SIZE: usize = 1_992;
pub const PERFORMANCE_SNAPSHOT_V4_SIZE: usize = 2_064;
pub const PERFORMANCE_SNAPSHOT_V5_SIZE: usize = 2_840;
pub const PERFORMANCE_SNAPSHOT_V6_SIZE: usize = 2_984;
pub const PERFORMANCE_CPU_SLOTS: usize = 64;

pub const PERFORMANCE_FLAG_INSTRUMENTED: u64 = 1 << 0;
pub const PERFORMANCE_FLAG_INVARIANT_TSC: u64 = 1 << 1;
pub const PERFORMANCE_FLAG_RDTSCP: u64 = 1 << 2;
pub const PERFORMANCE_FLAG_WEAK_SNAPSHOT: u64 = 1 << 3;

pub const CLOCK_SOURCE_UNAVAILABLE: u32 = 0;
pub const CLOCK_SOURCE_HYPERVISOR: u32 = 1;
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
    UserInterfaceStarted,
    UserInterfaceFirstFrame,
    Idle,
}

impl BootMilestone {
    pub const COUNT: usize = Self::Idle as usize + 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum HeapAllocationSizeClass {
    Bytes16,
    Bytes64,
    Bytes256,
    Bytes1024,
    Bytes4096,
    Bytes16384,
    Bytes65536,
    Bytes262144,
    Larger,
}

impl HeapAllocationSizeClass {
    pub const COUNT: usize = Self::Larger as usize + 1;

    pub const fn for_size(size: usize) -> Self {
        match size {
            0..=16 => Self::Bytes16,
            17..=64 => Self::Bytes64,
            65..=256 => Self::Bytes256,
            257..=1_024 => Self::Bytes1024,
            1_025..=4_096 => Self::Bytes4096,
            4_097..=16_384 => Self::Bytes16384,
            16_385..=65_536 => Self::Bytes65536,
            65_537..=262_144 => Self::Bytes262144,
            _ => Self::Larger,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum AllocationSubsystem {
    Other,
    Scheduler,
    Ipc,
    Vfs,
    PageFault,
    NetworkReceive,
    NetworkTransmit,
    BlockIo,
    ProcessCreation,
    ThreadCreation,
    Syscall,
}

impl AllocationSubsystem {
    pub const COUNT: usize = Self::Syscall as usize + 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum FrameAllocationFailure {
    AllocatorUnavailable,
    Exhausted,
    InvalidContiguousRequest,
    ContiguousUnavailable,
}

impl FrameAllocationFailure {
    pub const COUNT: usize = Self::ContiguousUnavailable as usize + 1;
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
pub struct FrameAllocatorSnapshot {
    pub requests: u64,
    pub free_list_hits: u64,
    pub bump_hits: u64,
    pub contiguous_requests: u64,
    pub memory_map_regions_examined: u64,
    pub zero_calls: u64,
    pub zero_bytes: u64,
    pub zero_cycles: u64,
    pub failures: [u64; FrameAllocationFailure::COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameFragmentationSnapshot {
    pub bump_free_pages: u64,
    pub recycled_pages: u64,
    pub largest_contiguous_pages: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameActivitySnapshot {
    pub allocated_pages_by_cpu: [u64; PERFORMANCE_CPU_SLOTS],
    pub allocated_pages_by_subsystem: [u64; AllocationSubsystem::COUNT],
    pub zero_calls_by_subsystem: [u64; AllocationSubsystem::COUNT],
    pub zero_cycles_by_subsystem: [u64; AllocationSubsystem::COUNT],
}

impl Default for FrameActivitySnapshot {
    fn default() -> Self {
        Self {
            allocated_pages_by_cpu: [0; PERFORMANCE_CPU_SLOTS],
            allocated_pages_by_subsystem: [0; AllocationSubsystem::COUNT],
            zero_calls_by_subsystem: [0; AllocationSubsystem::COUNT],
            zero_cycles_by_subsystem: [0; AllocationSubsystem::COUNT],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerQueueSnapshot {
    pub housekeeping: DistributionSnapshot,
    pub full_scans: u64,
    pub skipped_checks: u64,
    pub wakeups: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerActivitySnapshot {
    pub sleep_queue: TimerQueueSnapshot,
    pub futex_timeout_queue: TimerQueueSnapshot,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VfsActivitySnapshot {
    pub metadata_queries: u64,
    pub read_range_calls: u64,
    pub write_range_calls: u64,
    pub read_requested_bytes: u64,
    pub read_transferred_bytes: u64,
    pub write_requested_bytes: u64,
    pub write_transferred_bytes: u64,
    pub temporary_buffer_allocations: u64,
    pub temporary_buffer_bytes: u64,
    pub path_clone_allocations: u64,
    pub path_clone_bytes: u64,
}

impl VfsActivitySnapshot {
    pub fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            metadata_queries: self
                .metadata_queries
                .saturating_sub(earlier.metadata_queries),
            read_range_calls: self.read_range_calls.saturating_sub(earlier.read_range_calls),
            write_range_calls: self
                .write_range_calls
                .saturating_sub(earlier.write_range_calls),
            read_requested_bytes: self
                .read_requested_bytes
                .saturating_sub(earlier.read_requested_bytes),
            read_transferred_bytes: self
                .read_transferred_bytes
                .saturating_sub(earlier.read_transferred_bytes),
            write_requested_bytes: self
                .write_requested_bytes
                .saturating_sub(earlier.write_requested_bytes),
            write_transferred_bytes: self
                .write_transferred_bytes
                .saturating_sub(earlier.write_transferred_bytes),
            temporary_buffer_allocations: self
                .temporary_buffer_allocations
                .saturating_sub(earlier.temporary_buffer_allocations),
            temporary_buffer_bytes: self
                .temporary_buffer_bytes
                .saturating_sub(earlier.temporary_buffer_bytes),
            path_clone_allocations: self
                .path_clone_allocations
                .saturating_sub(earlier.path_clone_allocations),
            path_clone_bytes: self.path_clone_bytes.saturating_sub(earlier.path_clone_bytes),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// v2 extension. The v1 prefix above must remain byte-for-byte stable.
    pub heap_committed_bytes: u64,
    pub heap_internal_fragmentation: GaugeSnapshot,
    pub heap_allocations_by_size: [u64; HeapAllocationSizeClass::COUNT],
    pub heap_allocations_by_cpu: [u64; PERFORMANCE_CPU_SLOTS],
    pub heap_allocations_by_subsystem: [u64; AllocationSubsystem::COUNT],
    /// v3 extension. The v2 prefix above must remain byte-for-byte stable.
    pub frame_allocator: FrameAllocatorSnapshot,
    /// v4 extension. The v3 prefix above must remain byte-for-byte stable.
    pub frame_allocator_lock_wait: DistributionSnapshot,
    pub frame_fragmentation: FrameFragmentationSnapshot,
    /// v5 extension. The v4 prefix above must remain byte-for-byte stable.
    pub frame_activity: FrameActivitySnapshot,
    /// v6 extension. The v5 prefix above must remain byte-for-byte stable.
    pub timer_activity: TimerActivitySnapshot,
    /// v7 extension. The v6 prefix above must remain byte-for-byte stable.
    pub vfs_activity: VfsActivitySnapshot,
}

impl Default for KernelPerformanceSnapshot {
    fn default() -> Self {
        Self {
            version: 0,
            size: 0,
            flags: 0,
            tsc_frequency_khz: 0,
            clock_source: 0,
            kernel_stack_high_water_bytes: 0,
            usable_frames: 0,
            free_frames: 0,
            heap_capacity_bytes: 0,
            counters: [0; CounterMetric::COUNT],
            gauges: [GaugeSnapshot::default(); GaugeMetric::COUNT],
            latencies: [DistributionSnapshot::default(); LatencyMetric::COUNT],
            boot_timestamps: [0; BootMilestone::COUNT],
            heap_committed_bytes: 0,
            heap_internal_fragmentation: GaugeSnapshot::default(),
            heap_allocations_by_size: [0; HeapAllocationSizeClass::COUNT],
            heap_allocations_by_cpu: [0; PERFORMANCE_CPU_SLOTS],
            heap_allocations_by_subsystem: [0; AllocationSubsystem::COUNT],
            frame_allocator: FrameAllocatorSnapshot::default(),
            frame_allocator_lock_wait: DistributionSnapshot::default(),
            frame_fragmentation: FrameFragmentationSnapshot::default(),
            frame_activity: FrameActivitySnapshot::default(),
            timer_activity: TimerActivitySnapshot::default(),
            vfs_activity: VfsActivitySnapshot::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<DistributionSnapshot>(), 48);
        assert_eq!(core::mem::size_of::<GaugeSnapshot>(), 16);
        assert_eq!(
            core::mem::offset_of!(KernelPerformanceSnapshot, heap_committed_bytes),
            PERFORMANCE_SNAPSHOT_V1_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(KernelPerformanceSnapshot, frame_allocator),
            PERFORMANCE_SNAPSHOT_V2_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(KernelPerformanceSnapshot, frame_allocator_lock_wait),
            PERFORMANCE_SNAPSHOT_V3_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(KernelPerformanceSnapshot, frame_activity),
            PERFORMANCE_SNAPSHOT_V4_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(KernelPerformanceSnapshot, timer_activity),
            PERFORMANCE_SNAPSHOT_V5_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(KernelPerformanceSnapshot, vfs_activity),
            PERFORMANCE_SNAPSHOT_V6_SIZE
        );
        assert_eq!(core::mem::size_of::<KernelPerformanceSnapshot>(), 3_072);
        assert_eq!(core::mem::align_of::<KernelPerformanceSnapshot>(), 8);
    }

    #[test]
    fn allocation_size_classes_cover_boundaries() {
        assert_eq!(
            HeapAllocationSizeClass::for_size(16),
            HeapAllocationSizeClass::Bytes16
        );
        assert_eq!(
            HeapAllocationSizeClass::for_size(17),
            HeapAllocationSizeClass::Bytes64
        );
        assert_eq!(
            HeapAllocationSizeClass::for_size(262_144),
            HeapAllocationSizeClass::Bytes262144
        );
        assert_eq!(
            HeapAllocationSizeClass::for_size(262_145),
            HeapAllocationSizeClass::Larger
        );
    }

    #[test]
    fn vfs_activity_delta_does_not_underflow() {
        let earlier = VfsActivitySnapshot {
            metadata_queries: 7,
            temporary_buffer_bytes: 4_096,
            ..VfsActivitySnapshot::default()
        };
        let current = VfsActivitySnapshot {
            metadata_queries: 10,
            temporary_buffer_bytes: 2_048,
            ..VfsActivitySnapshot::default()
        };

        let delta = current.saturating_sub(earlier);
        assert_eq!(delta.metadata_queries, 3);
        assert_eq!(delta.temporary_buffer_bytes, 0);
    }
}

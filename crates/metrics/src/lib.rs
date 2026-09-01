#![no_std]

use core::array;
use core::sync::atomic::{AtomicU64, Ordering};

pub const HISTOGRAM_BUCKETS: usize = u64::BITS as usize + 1;

pub struct AtomicHistogram {
    buckets: [AtomicU64; HISTOGRAM_BUCKETS],
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
}

pub struct AtomicGauge {
    current: AtomicU64,
    peak: AtomicU64,
}

impl AtomicGauge {
    pub const fn new() -> Self {
        Self {
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        }
    }

    pub fn add(&self, value: u64) {
        let previous =
            match self
                .current
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(value))
                }) {
                Ok(previous) => previous,
                Err(current) => current,
            };
        self.peak
            .fetch_max(previous.saturating_add(value), Ordering::Relaxed);
    }

    pub fn subtract(&self, value: u64) {
        let _ = self
            .current
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(value))
            });
    }

    pub fn snapshot(&self) -> GaugeSnapshot {
        GaugeSnapshot {
            current: self.current.load(Ordering::Relaxed),
            peak: self.peak.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicGauge {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GaugeSnapshot {
    pub current: u64,
    pub peak: u64,
}

impl AtomicHistogram {
    pub const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; HISTOGRAM_BUCKETS],
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            max: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record(&self, value: u64) {
        saturating_add(&self.buckets[bucket_index(value)], 1);
        saturating_add(&self.count, 1);
        saturating_add(&self.sum, value);
        self.max.fetch_max(value, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed)),
            count: self.count.load(Ordering::Relaxed),
            sum: self.sum.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistogramSnapshot {
    pub buckets: [u64; HISTOGRAM_BUCKETS],
    pub count: u64,
    pub sum: u64,
    pub max: u64,
}

impl HistogramSnapshot {
    pub fn percentile(&self, numerator: u64, denominator: u64) -> Option<u64> {
        if self.count == 0 || denominator == 0 || numerator > denominator {
            return None;
        }

        let count = u128::from(self.count);
        let numerator = u128::from(numerator);
        let denominator = u128::from(denominator);
        let rank = ((count * numerator + denominator - 1) / denominator).max(1);
        let mut seen = 0u64;
        for (index, count) in self.buckets.iter().copied().enumerate() {
            seen = seen.saturating_add(count);
            if u128::from(seen) >= rank {
                return Some(bucket_upper_bound(index));
            }
        }

        Some(self.max)
    }

    pub fn mean(&self) -> Option<u64> {
        (self.count != 0).then(|| self.sum / self.count)
    }
}

#[inline]
fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[inline]
const fn bucket_index(value: u64) -> usize {
    if value == 0 {
        0
    } else {
        (u64::BITS - value.leading_zeros()) as usize
    }
}

const fn bucket_upper_bound(index: usize) -> u64 {
    match index {
        0 => 0,
        1..=63 => (1u64 << index) - 1,
        _ => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_zero_and_power_of_two_boundaries() {
        let histogram = AtomicHistogram::new();
        for value in [0, 1, 2, 3, 4, u64::MAX] {
            histogram.record(value);
        }

        let snapshot = histogram.snapshot();
        assert_eq!(snapshot.buckets[0], 1);
        assert_eq!(snapshot.buckets[1], 1);
        assert_eq!(snapshot.buckets[2], 2);
        assert_eq!(snapshot.buckets[3], 1);
        assert_eq!(snapshot.buckets[64], 1);
        assert_eq!(snapshot.count, 6);
        assert_eq!(snapshot.max, u64::MAX);
    }

    #[test]
    fn reports_bounded_percentiles() {
        let histogram = AtomicHistogram::new();
        for value in 1..=100 {
            histogram.record(value);
        }

        let snapshot = histogram.snapshot();
        assert_eq!(snapshot.percentile(50, 100), Some(63));
        assert_eq!(snapshot.percentile(95, 100), Some(127));
        assert_eq!(snapshot.percentile(99, 100), Some(127));
        assert_eq!(snapshot.mean(), Some(50));
    }

    #[test]
    fn rejects_empty_and_invalid_percentiles() {
        let snapshot = AtomicHistogram::new().snapshot();
        assert_eq!(snapshot.percentile(50, 100), None);
        assert_eq!(snapshot.percentile(1, 0), None);
        assert_eq!(snapshot.percentile(101, 100), None);
        assert_eq!(snapshot.mean(), None);
    }

    #[test]
    fn gauge_tracks_current_and_peak_values() {
        let gauge = AtomicGauge::new();
        gauge.add(40);
        gauge.add(2);
        gauge.subtract(10);
        gauge.add(5);

        assert_eq!(
            gauge.snapshot(),
            GaugeSnapshot {
                current: 37,
                peak: 42,
            }
        );
    }

    #[test]
    fn gauge_does_not_underflow() {
        let gauge = AtomicGauge::new();
        gauge.add(4);
        gauge.subtract(10);

        assert_eq!(gauge.snapshot().current, 0);
        assert_eq!(gauge.snapshot().peak, 4);
    }
}

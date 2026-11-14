//! Native byte-stream state; independent of usercopy and syscall selectors.
use super::{FileHandle, ThreadId};
use alloc::vec::Vec;
use mnu_abi::status::Error;

const MAX_PIPES: usize = 64;
pub(crate) const PIPE_BUFFER_CAP: usize = 64 * 1024;

struct PipeState {
    data: Vec<u8>,
    readers: usize,
    writers: usize,
    waiters: Vec<crate::task::ThreadId>,
}

impl PipeState {
    fn signals(&self, write_end: bool) -> u64 {
        self.signals_with_capacity(write_end, 1)
    }

    fn signals_with_capacity(&self, write_end: bool, minimum: usize) -> u64 {
        let mut signals = 0;
        if write_end {
            if self.readers == 0 {
                signals |= mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            } else if PIPE_BUFFER_CAP.saturating_sub(self.data.len()) >= minimum {
                signals |= mnu_abi::HANDLE_SIGNAL_WRITABLE;
            }
        } else {
            if !self.data.is_empty() || self.writers == 0 {
                signals |= mnu_abi::HANDLE_SIGNAL_READABLE;
            }
            if self.writers == 0 {
                signals |= mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            }
        }
        signals
    }
}

static PIPE_TABLE: crate::interrupt::spinlock::SpinLock<[Option<PipeState>; MAX_PIPES]> =
    crate::interrupt::spinlock::SpinLock::new([const { None }; MAX_PIPES]);

pub(crate) fn alloc_stream_state() -> Option<usize> {
    let mut table = PIPE_TABLE.lock();
    for (index, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(PipeState {
                data: Vec::new(),
                readers: 1,
                writers: 1,
                waiters: Vec::new(),
            });
            return Some(index);
        }
    }
    None
}

pub fn close_pipe_endpoint_from_kernel(pipe_id: usize, write_end: bool) {
    let waiters = {
        let mut table = PIPE_TABLE.lock();
        let Some(slot) = table.get_mut(pipe_id) else {
            return;
        };
        let Some(pipe) = slot.as_mut() else {
            return;
        };
        if write_end {
            pipe.writers = pipe.writers.saturating_sub(1);
        } else {
            pipe.readers = pipe.readers.saturating_sub(1);
        }
        let waiters = core::mem::take(&mut pipe.waiters);
        if pipe.readers == 0 && pipe.writers == 0 {
            *slot = None;
        }
        waiters
    };
    wake_stream_waiters(waiters);
}

fn wake_stream_waiters(waiters: Vec<crate::task::ThreadId>) {
    for waiter in waiters {
        crate::task::wake_registered_waiter(waiter);
    }
}

pub(crate) fn stream_signals(handle: &FileHandle) -> Result<u64, u64> {
    stream_signals_for_capacity(handle, 0)
}

pub(crate) fn stream_signals_for_capacity(handle: &FileHandle, minimum: u32) -> Result<u64, u64> {
    let Some((stream_id, write_end)) = handle.stream_endpoint() else {
        return Err(Error::InvalidArgument.into_raw());
    };
    if minimum != 0 && (!write_end || minimum as usize > PIPE_BUFFER_CAP) {
        return Err(Error::InvalidArgument.into_raw());
    }
    let table = PIPE_TABLE.lock();
    let Some(Some(stream)) = table.get(stream_id) else {
        return Err(Error::InvalidArgument.into_raw());
    };
    Ok(if minimum == 0 {
        stream.signals(write_end)
    } else {
        stream.signals_with_capacity(write_end, minimum as usize)
    })
}

pub(crate) fn register_stream_waiter(
    handle: &FileHandle,
    waiter: crate::task::ThreadId,
) -> Result<usize, u64> {
    let Some((stream_id, _)) = handle.stream_endpoint() else {
        return Err(Error::InvalidArgument.into_raw());
    };
    let mut table = PIPE_TABLE.lock();
    let Some(Some(stream)) = table.get_mut(stream_id) else {
        return Err(Error::InvalidArgument.into_raw());
    };
    if !stream.waiters.contains(&waiter) {
        if stream.waiters.try_reserve(1).is_err() {
            return Err(mnu_abi::status::Error::ResourceUnavailable.into_raw());
        }
        stream.waiters.push(waiter);
    }
    Ok(stream_id)
}

pub(crate) fn remove_stream_waiter(stream_id: usize, waiter: crate::task::ThreadId) {
    let mut table = PIPE_TABLE.lock();
    if let Some(Some(stream)) = table.get_mut(stream_id) {
        stream.waiters.retain(|candidate| *candidate != waiter);
    }
}

/// Wakeups run after releasing stream and caller-output locks.
pub(crate) struct Completed {
    count: usize,
    waiters: Vec<ThreadId>,
}
impl Completed {
    pub(crate) fn finish(self) -> usize {
        wake_stream_waiters(self.waiters);
        self.count
    }
}
fn register(pipe: &mut PipeState, current: ThreadId) -> Result<(), Error> {
    if !pipe.waiters.contains(&current) {
        pipe.waiters
            .try_reserve(1)
            .map_err(|_| Error::ResourceUnavailable)?;
        pipe.waiters.push(current);
    }
    Ok(())
}
pub(crate) fn read_ready(
    id: usize,
    maximum: usize,
    current: ThreadId,
    nonblocking: bool,
) -> Result<usize, Error> {
    let mut table = PIPE_TABLE.lock();
    let pipe = table
        .get_mut(id)
        .and_then(Option::as_mut)
        .ok_or(Error::InvalidArgument)?;
    if !pipe.data.is_empty() {
        return Ok(maximum.min(pipe.data.len()));
    }
    if pipe.writers == 0 {
        return Ok(0);
    }
    if !nonblocking {
        register(pipe, current)?;
    }
    Err(Error::NotReady)
}
pub(crate) fn consume(
    id: usize,
    maximum: usize,
    current: ThreadId,
    copy: impl FnOnce(&[u8]) -> Result<(), Error>,
) -> Result<Option<Completed>, Error> {
    let mut table = PIPE_TABLE.lock();
    let pipe = table
        .get_mut(id)
        .and_then(Option::as_mut)
        .ok_or(Error::InvalidArgument)?;
    let count = maximum.min(pipe.data.len());
    if count == 0 {
        return Ok(None);
    }
    copy(&pipe.data[..count])?;
    pipe.data.drain(..count);
    pipe.waiters.retain(|waiter| *waiter != current);
    Ok(Some(Completed {
        count,
        waiters: core::mem::take(&mut pipe.waiters),
    }))
}
pub(crate) fn write_ready(
    id: usize,
    bytes: &[u8],
    complete: bool,
    current: ThreadId,
    nonblocking: bool,
) -> Result<Completed, Error> {
    let mut table = PIPE_TABLE.lock();
    let pipe = table
        .get_mut(id)
        .and_then(Option::as_mut)
        .ok_or(Error::InvalidArgument)?;
    if pipe.readers == 0 {
        return Err(Error::PeerClosed);
    }
    let available = PIPE_BUFFER_CAP.saturating_sub(pipe.data.len());
    let count = if complete && available < bytes.len() {
        0
    } else {
        available.min(bytes.len())
    };
    if count != 0 {
        pipe.data
            .try_reserve(count)
            .map_err(|_| Error::ResourceUnavailable)?;
        pipe.data.extend_from_slice(&bytes[..count]);
        pipe.waiters.retain(|waiter| *waiter != current);
        return Ok(Completed {
            count,
            waiters: core::mem::take(&mut pipe.waiters),
        });
    }
    if !nonblocking {
        register(pipe, current)?;
    }
    Err(Error::NotReady)
}
#[cfg(test)]
mod stream_tests {
    use super::{PipeState, PIPE_BUFFER_CAP};

    #[test]
    fn stream_signals_cover_data_capacity_and_peer_closure() {
        let mut stream = PipeState {
            data: alloc::vec::Vec::new(),
            readers: 1,
            writers: 1,
            waiters: alloc::vec::Vec::new(),
        };
        assert_eq!(stream.signals(false), 0);
        assert_eq!(stream.signals(true), mnu_abi::HANDLE_SIGNAL_WRITABLE);

        stream.data.resize(PIPE_BUFFER_CAP, 0);
        assert_eq!(stream.signals(false), mnu_abi::HANDLE_SIGNAL_READABLE);
        assert_eq!(stream.signals(true), 0);

        stream.writers = 0;
        assert_eq!(
            stream.signals(false),
            mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
        );
        stream.readers = 0;
        assert_eq!(stream.signals(true), mnu_abi::HANDLE_SIGNAL_PEER_CLOSED);
    }
}

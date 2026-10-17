//! ファイルシステム関連のシステムコール

use mnu_abi::status::Error;
use crate::task::fd_table::{FileHandle, FileHandleCap};
use alloc::vec::Vec;

const MAX_IO_BYTES: usize = 128 * 1024 * 1024;
const MAX_PIPES: usize = 64;
const PIPE_BUFFER_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeekBasis {
    Start,
    Current,
    End,
}

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

pub(crate) fn file_handle_options(handle: &FileHandle) -> Result<u64, u64> {
    let open = handle.open.lock();
    if open.pipe_id.is_none() {
        return Err(Error::InvalidArgument.into_raw());
    }
    Ok(open.io_options)
}

pub(crate) fn set_file_handle_options(handle: &FileHandle, options: u64) -> Result<(), u64> {
    if options & !mnu_abi::HANDLE_OPTIONS_ALL != 0 {
        return Err(Error::InvalidArgument.into_raw());
    }
    let mut open = handle.open.lock();
    if open.pipe_id.is_none() {
        return Err(Error::InvalidArgument.into_raw());
    }
    open.io_options = options;
    Ok(())
}

pub(crate) fn read_file_handle(handle: &FileHandle, buf_ptr: u64, len: u64) -> u64 {
    if buf_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    if len == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, len) {
        return Error::InvalidAddress.into_raw();
    }
    if !handle.cap.contains(FileHandleCap::READ) {
        return Error::AccessDenied.into_raw();
    }
    let open = handle.open.lock();
    let Some(pipe_id) = open.pipe_id else {
        return Error::InvalidArgument.into_raw();
    };
    let io_options = open.io_options;
    drop(open);
    read_pipe(pipe_id, io_options, buf_ptr, len)
}

fn read_pipe(pipe_id: usize, io_options: u64, buf_ptr: u64, len: u64) -> u64 {
    let target_len = match usize::try_from(len) {
        Ok(v) => v.min(MAX_IO_BYTES),
        Err(_) => MAX_IO_BYTES,
    };
    let Some(current) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    loop {
        let mut table = PIPE_TABLE.lock();
        let Some(Some(pipe)) = table.get_mut(pipe_id) else {
            return Error::InvalidArgument.into_raw();
        };
        if pipe.data.is_empty() {
            if pipe.writers == 0 {
                return 0;
            }
            if (io_options & mnu_abi::HANDLE_OPTION_NONBLOCKING) != 0 {
                return Error::NotReady.into_raw();
            }
            if !pipe.waiters.contains(&current) {
                if pipe.waiters.try_reserve(1).is_err() {
                    return mnu_abi::status::Error::ResourceUnavailable.into_raw();
                }
                pipe.waiters.push(current);
            }
            drop(table);
            if super::upcall::current_has_deliverable_upcall() {
                remove_stream_waiter(pipe_id, current);
                return Error::NotReady.into_raw();
            }
            let _ = crate::task::sleep_thread_unless_woken(current);
            crate::task::yield_now();
            continue;
        }
        let take = core::cmp::min(pipe.data.len(), target_len);
        drop(table);
        // Fault/COW preparation can invoke a provider that uses this stream.
        // Prepare without PIPE, then acquire PROC -> PIPE for resident copying.
        let result = super::with_user_output_native(buf_ptr, take, |copy| {
            let mut table = PIPE_TABLE.lock();
            let Some(Some(pipe)) = table.get_mut(pipe_id) else {
                return Err(Error::InvalidArgument);
            };
            let count = core::cmp::min(take, pipe.data.len());
            if count == 0 {
                return Ok(None);
            }
            copy(&pipe.data[..count])?;
            pipe.data.drain(0..count);
            pipe.waiters.retain(|waiter| *waiter != current);
            Ok(Some((count, core::mem::take(&mut pipe.waiters))))
        });
        match result {
            Ok(Some((count, waiters))) => {
                wake_stream_waiters(waiters);
                return count as u64;
            }
            Ok(None) => continue,
            Err(error) => return error.into_raw(),
        }
    }
}

pub(crate) fn write_file_handle(handle: &FileHandle, buf_ptr: u64, len: u64) -> u64 {
    if buf_ptr == 0 {
        return Error::InvalidAddress.into_raw();
    }
    if len == 0 {
        return 0;
    }
    if !crate::syscall::validate_user_ptr(buf_ptr, len) {
        return Error::InvalidAddress.into_raw();
    }
    if !handle.cap.contains(FileHandleCap::WRITE) {
        return Error::AccessDenied.into_raw();
    }
    let open = handle.open.lock();
    let Some(pipe_id) = open.pipe_id else {
        return Error::InvalidArgument.into_raw();
    };
    let io_options = open.io_options;
    drop(open);
    write_pipe(pipe_id, io_options, buf_ptr, len, true)
}

pub(crate) fn read_stream_handle(
    handle: &FileHandle,
    buffer: u64,
    length: u64,
    options: u64,
) -> u64 {
    if !handle.cap.contains(FileHandleCap::READ) {
        return Error::AccessDenied.into_raw();
    }
    if length == 0 {
        return 0;
    }
    if buffer == 0 || !crate::syscall::validate_user_ptr(buffer, length) {
        return Error::InvalidAddress.into_raw();
    }
    let open = handle.open.lock();
    let Some(stream_id) = open.pipe_id else {
        return Error::InvalidArgument.into_raw();
    };
    if open.pipe_write {
        return Error::InvalidArgument.into_raw();
    }
    let io_options = open.io_options
        | if options & mnu_abi::STREAM_IO_TRY != 0 {
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        } else {
            0
        };
    drop(open);
    read_pipe(stream_id, io_options, buffer, length)
}

pub(crate) fn write_stream_handle(
    handle: &FileHandle,
    buffer: u64,
    length: u64,
    options: u64,
) -> u64 {
    if !handle.cap.contains(FileHandleCap::WRITE) {
        return Error::AccessDenied.into_raw();
    }
    let open = handle.open.lock();
    let Some(stream_id) = open.pipe_id else {
        return Error::InvalidArgument.into_raw();
    };
    if !open.pipe_write {
        return Error::InvalidArgument.into_raw();
    }
    let io_options = open.io_options
        | if options & mnu_abi::STREAM_IO_TRY != 0 {
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        } else {
            0
        };
    drop(open);
    write_pipe(
        stream_id,
        io_options,
        buffer,
        length,
        options & mnu_abi::STREAM_WRITE_COMPLETE != 0,
    )
}

fn write_pipe(pipe_id: usize, io_options: u64, buf_ptr: u64, len: u64, complete: bool) -> u64 {
    let Ok(len_usize) = usize::try_from(len) else {
        return Error::InvalidArgument.into_raw();
    };
    if complete && len_usize > PIPE_BUFFER_CAP {
        return Error::InvalidArgument.into_raw();
    }
    if len_usize == 0 {
        return 0;
    }
    let mut tmp = Vec::new();
    let temporary_length = len_usize.min(PIPE_BUFFER_CAP);
    if tmp.try_reserve_exact(temporary_length).is_err() {
        return mnu_abi::status::Error::ResourceUnavailable.into_raw();
    }
    tmp.resize(temporary_length, 0);
    crate::performance::record_vfs_temporary_buffer(tmp.len());
    if let Err(error) = crate::syscall::copy_from_user_native(buf_ptr, &mut tmp) {
        return error.into_raw();
    }
    let Some(current) = crate::task::current_thread_id() else {
        return Error::NotReady.into_raw();
    };
    loop {
        let mut table = PIPE_TABLE.lock();
        let Some(Some(pipe)) = table.get_mut(pipe_id) else {
            return Error::InvalidArgument.into_raw();
        };
        if pipe.readers == 0 {
            return mnu_abi::status::Error::PeerClosed.into_raw();
        }
        let available = PIPE_BUFFER_CAP.saturating_sub(pipe.data.len());
        let count = if complete {
            if available >= tmp.len() { tmp.len() } else { 0 }
        } else {
            available.min(tmp.len())
        };
        if count != 0 {
            if pipe.data.try_reserve(count).is_err() {
                return mnu_abi::status::Error::ResourceUnavailable.into_raw();
            }
            pipe.data.extend_from_slice(&tmp[..count]);
            pipe.waiters.retain(|waiter| *waiter != current);
            let waiters = core::mem::take(&mut pipe.waiters);
            drop(table);
            wake_stream_waiters(waiters);
            return count as u64;
        }
        if (io_options & mnu_abi::HANDLE_OPTION_NONBLOCKING) != 0 {
            return Error::NotReady.into_raw();
        }
        if !pipe.waiters.contains(&current) {
            if pipe.waiters.try_reserve(1).is_err() {
                return mnu_abi::status::Error::ResourceUnavailable.into_raw();
            }
            pipe.waiters.push(current);
        }
        drop(table);
        if super::upcall::current_has_deliverable_upcall() {
            remove_stream_waiter(pipe_id, current);
            return Error::NotReady.into_raw();
        }
        let _ = crate::task::sleep_thread_unless_woken(current);
        crate::task::yield_now();
    }
}

#[cfg(test)]
mod stream_tests {
    use super::{PIPE_BUFFER_CAP, PipeState};

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

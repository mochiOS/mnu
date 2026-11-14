//! Native stream usercopy and blocking I/O adapters.

use crate::task::fd_table::{FileHandle, FileHandleCap};
use alloc::vec::Vec;
use mnu_abi::status::Error;

const MAX_IO_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeekBasis {
    Start,
    Current,
    End,
}

pub(crate) use crate::task::stream::{
    alloc_stream_state, register_stream_waiter, remove_stream_waiter, stream_signals_for_capacity,
    PIPE_BUFFER_CAP,
};

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
    let nonblocking = io_options & mnu_abi::HANDLE_OPTION_NONBLOCKING != 0;
    loop {
        let take = match crate::task::stream::read_ready(pipe_id, target_len, current, nonblocking)
        {
            Ok(0) => return 0,
            Ok(take) => take,
            Err(Error::NotReady) if !nonblocking => {
                if let Err(error) = wait_for_stream(pipe_id, current) {
                    return error.into_raw();
                }
                continue;
            }
            Err(error) => return error.into_raw(),
        };
        // Prepare faults without stream exclusion, then copy under PROC -> STREAM.
        let result = super::with_user_output_native(buf_ptr, take, |copy| {
            crate::task::stream::consume(pipe_id, take, current, copy)
        });
        match result {
            Ok(Some(completed)) => return completed.finish() as u64,
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
    let tmp = match crate::task::operation::Scope::new(tmp) {
        Ok(tmp) => tmp,
        Err(error) => return error.into_raw(),
    };
    let nonblocking = io_options & mnu_abi::HANDLE_OPTION_NONBLOCKING != 0;
    loop {
        match crate::task::stream::write_ready(pipe_id, &tmp, complete, current, nonblocking) {
            Ok(completed) => return completed.finish() as u64,
            Err(Error::NotReady) if !nonblocking => {
                if let Err(error) = wait_for_stream(pipe_id, current) {
                    return error.into_raw();
                }
            }
            Err(error) => return error.into_raw(),
        }
    }
}

fn wait_for_stream(stream: usize, current: crate::task::ThreadId) -> Result<(), Error> {
    if super::upcall::current_has_deliverable_upcall() {
        remove_stream_waiter(stream, current);
        return Err(Error::NotReady);
    }
    let _ = crate::task::sleep_thread_unless_woken(current);
    crate::task::yield_now();
    Ok(())
}

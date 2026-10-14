//! Sample launches require the userspace policy authority and installed package
//! records, just like normal launches. No caller-selected capability list or
//! special init bypass is accepted. Child references are retained until exit.

use mochi_user_platform as platform;
use platform::syscall::{EINVAL, EIO, ENOENT, EOVERFLOW, SysError};

pub(crate) struct Child {
    handle: u32,
    exited: bool,
}

impl Child {
    pub(crate) fn wait(&mut self) -> Result<i32, SysError> {
        let status = platform::process::wait_handle(self.handle, mnu_abi::PROCESS_WAIT_INFINITE)?;
        if status.state != mnu_abi::PROCESS_STATE_EXITED {
            return Err(SysError::from_raw(EIO as i64));
        }
        self.exited = true;
        Ok((status.exit_code as i32 & 0xff) << 8)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.exited {
            terminate_until_exited(self.handle);
        }
        let _ = platform::handle::close(self.handle);
    }
}

fn terminate_until_exited(handle: u32) {
    loop {
        if platform::process::handle_status(handle)
            .is_ok_and(|status| status.state == mnu_abi::PROCESS_STATE_EXITED)
        {
            return;
        }
        let _ = platform::process::terminate_handle(handle, 127);
        let _ = platform::thread::sleep_milliseconds(1);
    }
}

pub(crate) fn spawn(path: &str) -> Result<Child, SysError> {
    let endpoint = platform::process::find_by_name("capability.service")?;
    if endpoint == 0 {
        return Err(SysError::from_raw(ENOENT as i64));
    }
    let endpoint = u32::try_from(endpoint).map_err(|_| SysError::from_raw(EOVERFLOW as i64))?;
    let label = path
        .rsplit('/')
        .next()
        .filter(|label| !label.is_empty())
        .ok_or(SysError::from_raw(EINVAL as i64))?;
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let metadata =
        mochios_posix_client::launch_arguments::encode_native_launch(path, label, &[], random)
            .map_err(|_| SysError::from_raw(EINVAL as i64))?;
    let image = platform::capability::prepare_execution_image(
        endpoint,
        path,
        platform::service::ExecutionClass::Unprivileged,
    )?;
    let (handle, _) = mochios_posix_client::process_creation::create_with_rollback(
        || platform::process::create_stopped(image.handle(), &metadata),
        |_| Ok(()),
        |handle| platform::process::handle_status(handle).map(|status| status.process_id),
        platform::process::resume_handle,
        |handle| {
            let _ = platform::process::terminate_handle(handle, 127);
        },
        |handle| {
            terminate_until_exited(handle);
            let _ = platform::handle::close(handle);
        },
    )?;
    Ok(Child {
        handle,
        exited: false,
    })
}

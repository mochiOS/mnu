//! I/O関連のシステムコール

use super::types::{EBADF, EFAULT, EINVAL, SUCCESS};
use crate::util::console;
use crate::{debug, error, info, warn};

/// 標準出力のファイルディスクリプタ
const STDOUT_FD: u64 = 1;
/// 標準エラー出力のファイルディスクリプタ
const STDERR_FD: u64 = 2;

/// Writeシステムコール
///
/// # 引数
/// - `fd`: ファイルディスクリプタ (1=stdout, 2=stderr, >=3=ファイル/パイプ)
/// - `buf_ptr`: 書き込むデータのポインタ
/// - `len`: 書き込むデータの長さ
///
/// # 戻り値
/// 書き込んだバイト数、またはエラーコード
pub fn write(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    debug!("write: fd={}, buf_ptr={:#x}, len={}", fd, buf_ptr, len);

    if len == 0 {
        return SUCCESS;
    }
    if buf_ptr == 0 {
        return EFAULT;
    }

    if fd >= 3 {
        return crate::syscall::fs::write(fd, buf_ptr, len);
    }

    if fd != STDOUT_FD && fd != STDERR_FD {
        return EBADF;
    }

    let mut buf = alloc::vec![0u8; len as usize];
    if let Err(err) = crate::syscall::copy_from_user(buf_ptr, &mut buf) {
        return err;
    }

    // シリアルには常に出力する（デバッグ用）
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut serial = console::SERIAL.lock();
        for &byte in &buf {
            serial.send_byte(byte);
        }
    });

    len
}

/// Readシステムコール
/// - fd >= 3 の場合はファイルシステムへ委譲する
pub fn read(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    use super::types::EFAULT;

    if buf_ptr == 0 {
        return EFAULT;
    }
    if len == 0 {
        return 0;
    }

    if fd >= 3 {
        return crate::syscall::fs::read(fd, buf_ptr, len);
    }

    // fd=1,2 への read は無効
    EBADF
}

/// Logシステムコール
///
/// カーネルログにメッセージを書き込む
/// # 引数
/// msg: メッセージ
/// len: メッセージの長さ
/// level: ログレベル（0=ERROR、1=WARNING、2=INFO、3=DEBUG）
///
/// # 戻り値
/// 成功時はSUCCESS、エラー時はエラーコード
pub fn log(msg: u64, len: u64, level: u64) -> u64 {
    if msg == 0 || len == 0 {
        return super::types::EINVAL;
    }

    let mut copied = alloc::vec![0u8; len as usize];
    if let Err(err) = crate::syscall::copy_from_user(msg, &mut copied) {
        return err;
    }

    let msg = match core::str::from_utf8(&copied) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    match level {
        0 => error!("{}", msg),
        1 => warn!("{}", msg),
        2 => info!("{}", msg),
        3 => debug!("{}", msg),
        _ => return EINVAL,
    }
    SUCCESS
}

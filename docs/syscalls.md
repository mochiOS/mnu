# システムコール

syscall は、ユーザー空間からカーネルへ機能を依頼する API です。

## 読む順番

- [安全なユーザーアクセス](./syscalls/user-access.md)
- [dispatch](./syscalls/dispatch.md)
- [exec](./syscalls/exec.md)
- [fs](./syscalls/fs.md)
- [time と signal](./syscalls/time-signal.md)

## 関連ファイル

- [`src/syscall/mod.rs`](../src/syscall/mod.rs)
- [`src/syscall/syscall_entry.rs`](../src/syscall/syscall_entry.rs)
- [`src/syscall/exec.rs`](../src/syscall/exec.rs)
- [`src/syscall/fs.rs`](../src/syscall/fs.rs)
- [`src/syscall/process.rs`](../src/syscall/process.rs)
- [`src/syscall/time.rs`](../src/syscall/time.rs)
- [`src/syscall/signal.rs`](../src/syscall/signal.rs)

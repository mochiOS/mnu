---
title: システムコール
permalink: /docs/syscalls/
---

# システムコール

syscall は、ユーザー空間からカーネルへ機能を依頼する API です。

## 読む順番

- [安全なユーザーアクセス](/docs/syscalls/user-access/)
- [dispatch](/docs/syscalls/dispatch/)
- [exec](/docs/syscalls/exec/)
- [fs](/docs/syscalls/fs/)
- [time と signal](/docs/syscalls/time-signal/)

## 関連ファイル

- `src/syscall/mod.rs`
- `src/syscall/syscall_entry.rs`
- `src/syscall/exec.rs`
- `src/syscall/fs.rs`
- `src/syscall/process.rs`
- `src/syscall/time.rs`
- `src/syscall/signal.rs`

# mnu カーネル

このファイルはリポジトリ用の案内です。公開ページは [docs/index.md](/docs/) を使ってください。

## 読み順

1. [全体像](/docs/overview/)
2. [起動](/docs/boot/)
3. [メモリ](/docs/memory/)
4. [割り込み](/docs/interrupts/)
5. [タスク](/docs/tasks/)
6. [システムコール](/docs/syscalls/)
7. [ファイルシステム](/docs/filesystems/)
8. [capability とポリシー](/docs/capabilities-policy/)
9. [開発者向けメモ](/docs/development/)

## コードを追う起点

- `src/entry.rs`
- `src/kernel.rs`
- `src/init/mod.rs`
- `src/mem/mod.rs`
- `src/interrupt/mod.rs`
- `src/task/mod.rs`
- `src/syscall/mod.rs`
- `src/init/fs.rs`
- `src/kmod/mod.rs`

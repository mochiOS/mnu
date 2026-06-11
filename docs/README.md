# mnu カーネル

このドキュメントは、`mnu` カーネルの仕組みを順に理解したい人と、実装を追いながら変更したい開発者の両方を対象にしています。

読み方はシンプルです。最初に全体像をつかみ、そのあと起動、メモリ、割り込み、タスク、syscall、ファイルシステム、権限、開発メモの順に進めてください。

## 読み順

1. [全体像](./overview.md)
2. [起動](./boot.md)
3. [メモリ](./memory.md)
4. [割り込み](./interrupts.md)
5. [タスク](./tasks.md)
6. [システムコール](./syscalls.md)
7. [ファイルシステム](./filesystems.md)
8. [capability とポリシー](./capabilities-policy.md)
9. [開発者向けメモ](./development.md)

## コードを追う起点

- [`src/entry.rs`](../src/entry.rs)
- [`src/kernel.rs`](../src/kernel.rs)
- [`src/init/mod.rs`](../src/init/mod.rs)
- [`src/mem/mod.rs`](../src/mem/mod.rs)
- [`src/interrupt/mod.rs`](../src/interrupt/mod.rs)
- [`src/task/mod.rs`](../src/task/mod.rs)
- [`src/syscall/mod.rs`](../src/syscall/mod.rs)
- [`src/init/fs.rs`](../src/init/fs.rs)
- [`src/kmod/mod.rs`](../src/kmod/mod.rs)

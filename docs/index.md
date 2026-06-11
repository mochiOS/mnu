---
title: mnu カーネル
permalink: /docs/
---

# mnu カーネル

このドキュメントは、`mnu` カーネルの仕組みを順に理解したい人と、実装を追いながら変更したい開発者の両方を対象にしています。

読み方はシンプルです。最初に全体像をつかみ、そのあと起動、メモリ、割り込み、タスク、システムコール、ファイルシステム、権限、開発メモの順に進めてください。

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

## まず読むとよいページ

- [全体像](/docs/overview/)
- [起動](/docs/boot/)
- [メモリ](/docs/memory/)
- [タスク](/docs/tasks/)

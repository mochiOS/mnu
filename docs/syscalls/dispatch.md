---
title: dispatch
permalink: /docs/syscalls/dispatch/
---

# dispatch

`dispatch()` は syscall 番号を各処理へ振り分けます。

## 主な分類

- I/O
- FS
- process
- memory
- signal
- time
- IPC
- privilege

## 重要な点

syscall を増やすときは、単に match を増やすだけでは足りません。

- 引数の検証
- ユーザーコピー
- 権限チェック
- errno の返し方

まで含めて設計します。

## 関連ファイル

- `src/syscall/mod.rs`

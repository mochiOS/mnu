---
title: exec
permalink: /docs/syscalls/exec/
---

# exec

`exec` は、新しいプログラムを起動するための中核機能です。

## この syscall がやること

- 実行ファイルを読む
- ELF を検証する
- 新しい address space を作る
- 初期 stack を作る
- TLS や ASLR を設定する
- capability と起動ポリシーを反映する
- 最後にユーザーモードへ入る

## なぜ重いのか

`exec` は「新しいコードを走らせる」だけではありません。
その process の初期状態を全部作り直します。

## 関連ファイル

- `src/syscall/exec.rs`
- `src/policy/mod.rs`
- `src/task/usermode.rs`

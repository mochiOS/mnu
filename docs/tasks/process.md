---
title: process
permalink: /docs/tasks/process/
---

# process

process は、メモリ空間と資源をまとめる単位です。

## 持っているもの

- process ID
- 名前
- privilege
- capability
- 親 PID
- page table
- heap 範囲
- stack 範囲
- cwd
- 実行ファイルパス
- 優先度
- FD テーブル
- signal 状態

## 何を意味するか

process は「何を実行しているか」だけでなく、「どの権限で、どの資源を持っているか」も表します。

## 関連ファイル

- `src/task/process.rs`
- `src/task/fd_table.rs`
- `src/task/signal.rs`

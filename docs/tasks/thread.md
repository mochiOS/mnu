---
title: thread
permalink: /docs/tasks/thread/
---

# thread

thread は、CPU で実際に走る単位です。

## 持っているもの

- thread ID
- process への所属
- CPU context
- kernel stack
- user entry / user stack
- syscall 中かどうか
- FS base
- futex や wakeup の補助状態

## 見方

process が「箱」なら、thread は「中で動く一本の流れ」です。

## 関連ファイル

- `src/task/thread.rs`
- `src/task/context.rs`

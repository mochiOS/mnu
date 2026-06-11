---
title: タスク
permalink: /docs/tasks/
---

# タスク

このカーネルでは、実行単位を `process` と `thread` に分けています。

- process は資源と権限を持つ
- thread は CPU で実際に走る

## まず読むページ

- [process](/docs/tasks/process/)
- [thread](/docs/tasks/thread/)
- [scheduler](/docs/tasks/scheduler/)

## 関連ファイル

- `src/task/mod.rs`
- `src/task/process.rs`
- `src/task/thread.rs`
- `src/task/context.rs`
- `src/task/scheduler.rs`
- `src/task/usermode.rs`

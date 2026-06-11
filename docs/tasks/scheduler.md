---
title: scheduler
permalink: /docs/tasks/scheduler/
---

# scheduler

scheduler は、次にどの thread を動かすかを決めます。

## 基本の流れ

1. timer interrupt が来る
2. tick を進める
3. time slice が尽きたら再スケジュールする
4. Ready な thread を選ぶ
5. context switch する

## 調整の考え方

このカーネルでは、foreground、優先度、interactive 性、CPU 負荷傾向を見て量子を調整します。

## 開発者向け

context switch を触るときは、`TSS.RSP0` と syscall 用の kernel RSP も一緒に見てください。

## 関連ファイル

- `src/task/scheduler.rs`
- `src/task/context.rs`

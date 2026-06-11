---
title: タイマー
permalink: /docs/interrupts/timer/
---

# タイマー

`src/interrupt/timer.rs` は、PIT を使った時間管理を担います。

## 何をしているか

- 500 Hz の tick を刻む
- `sleep` の起床条件を確認する
- futex のタイムアウトを処理する
- スケジューラの時間切れを判定する

## 直感的な理解

タイマーは、OS の心拍です。
この心拍があるから、CPU に仕事を順番に割り振れます。

## 関連ファイル

- `src/interrupt/timer.rs`
- `src/syscall/time.rs`
- `src/task/scheduler.rs`

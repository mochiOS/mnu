---
title: time と signal
permalink: /docs/syscalls/time-signal/
---

# time と signal

## time

時間系 syscall は、tick を基準に動きます。

- `get_ticks`
- `clock_gettime`
- `sleep`

sleep 中の thread は timer interrupt で起こされます。

## signal

シグナルは、プロセスに対する非同期通知です。

- `rt_sigaction`
- `rt_sigprocmask`
- `kill`
- `tkill`
- `tgkill`

## 直感的な理解

signal は「後で処理してほしい通知」、sleep は「指定時刻まで待つ」仕組みです。

## 関連ファイル

- `src/syscall/time.rs`
- `src/syscall/signal.rs`

# mnu System Call Reference

この文書は、mnuが公開するシステムコールABIを定義します。

mnuのシステムコールは、カーネルが直接提供する最小の実行基盤です。ファイルシステム、GPU、ネットワーク、GUI、デバイス操作などの高レベル機能は、専用システムコールとして公開しません。これらは高速IPC、共有メモリ、Capability、eventを組み合わせて、サービスまたはcext経由で提供します。

## 基本方針

mnuのシステムコールは、次の領域だけを扱います。

* Process / Thread
* Memory / VM
* IPC
* Capability
* Event
* Time
* I/O

カーネルは、パス名、アプリケーション名、ウィンドウ、ソケット、GPUコマンド、デバイス名などの高レベル概念を直接ABIとして持ちません。

## 戻り値

すべてのシステムコールは、成功時に0以上の値を返します。

失敗時は負のエラーコードを返します。

```
>= 0  成功
<  0  エラー
```

## 共通エラー

```
EINVAL        引数が不正
EFAULT        ユーザーポインタが不正
EPERM         権限がない
ENOENT        対象が存在しない
EBADCAP       Capabilityが不正
ENOSYS        未実装
ENOMEM        メモリ不足
EAGAIN        現在は処理できない
ETIMEOUT      タイムアウト
EOVERFLOW     サイズまたは値が範囲外
EMSGSIZE      メッセージサイズが上限を超えた
EDEADLK       デッドロックの可能性がある
```

## 共通型

```
pid_t      プロセスID
tid_t      スレッドID
cap_t      Capability handle
event_t    Event capability
usize      アーキテクチャ依存の符号なし整数
isize      アーキテクチャ依存の符号付き整数
u64        64bit符号なし整数
i64        64bit符号付き整数
ptr        ユーザー空間ポインタ
```

## システムコール一覧

| 分類               | syscall               |
|------------------|-----------------------|
| Process / Thread | process_exit          |
| Process / Thread | process_spawn         |
| Process / Thread | process_wait          |
| Process / Thread | thread_create         |
| Process / Thread | thread_exit           |
| Process / Thread | thread_yield          |
| Memory / VM      | memory_alloc          |
| Memory / VM      | memory_free           |
| Memory / VM      | memory_map            |
| Memory / VM      | memory_unmap          |
| Memory / VM      | memory_protect        |
| Memory / VM      | memory_share          |
| Memory / VM      | memory_sync           |
| Physical Memory  | memory_phys_translate |
| Physical Memory  | memory_phys_map       |
| IPC              | ipc_create            |
| IPC              | ipc_send              |
| IPC              | ipc_recv              |
| IPC              | ipc_call              |
| IPC              | ipc_reply             |
| IPC              | ipc_wait              |
| Capability       | cap_clone             |
| Capability       | cap_drop              |
| Capability       | cap_transfer          |
| Capability       | cap_query             |
| Capability       | cap_restrict          |
| Event            | event_create          |
| Event            | event_wait            |
| Event            | event_signal          |
| Event            | event_poll            |
| Time             | time_now              |
| Time             | sleep                 |
| I/O              | write                 |
| Filesystem       | file_open             |
| Filesystem       | file_open_at          |
| Filesystem       | file_close            |
| Filesystem       | file_read             |
| Filesystem       | file_write            |
| Filesystem       | file_seek             |
| Filesystem       | file_stat             |
| Filesystem       | file_stat_at          |
| Filesystem       | file_fstat            |
| Filesystem       | file_read_dir         |
| Filesystem       | file_create_dir       |
| Filesystem       | file_remove           |
| Filesystem       | file_rename           |
| Filesystem       | file_sync             |

## Process / Thread

### process_exit

現在のプロセスを終了します。

```
process_exit(status: i64) -> never
```

`status` は親プロセスや監視側へ返される終了コードです。

このシステムコールは成功時に呼び出し元へ戻りません。

### process_spawn

新しいプロセスを生成します。

```
process_spawn(image_cap: cap_t, args_ptr: ptr, args_len: usize, flags: u64) -> pid_t
```

`image_cap` は実行可能イメージ、または将来のローダに渡される実行対象を示すCapabilityです。

`args_ptr` と `args_len` は起動引数領域を表します。

`flags` は生成オプションです。

実装がまだ存在しない場合は、成功扱いにせず `ENOSYS` を返します。

### process_wait

指定したプロセスの終了を待機します。

```
process_wait(pid: pid_t, status_ptr: ptr, flags: u64) -> isize
```

`pid` は待機対象のプロセスIDです。

`status_ptr` には終了ステータスを書き込みます。

`flags` により、ブロッキング待機または非ブロッキング待機を指定できます。

### thread_create

現在のプロセス内に新しいスレッドを作成します。

```
thread_create(entry: ptr, arg: usize, stack: ptr, stack_len: usize, flags: u64) -> tid_t
```

`entry` はスレッド開始関数です。

`arg` は開始関数に渡される引数です。

`stack` と `stack_len` はユーザー空間スタックを表します。

不正なentry、stack、stack_lenは `EINVAL` または `EFAULT` とします。

### thread_exit

現在のスレッドを終了します。

```
thread_exit(status: i64) -> never
```

最後のスレッドが終了した場合、そのプロセスも終了します。

このシステムコールは成功時に呼び出し元へ戻りません。

### thread_yield

現在のスレッドが自発的にCPUを手放します。

```
thread_yield() -> isize
```

スケジューラは別の実行可能スレッドへ切り替えることができます。

## Memory / VM

### memory_alloc

匿名メモリを確保します。

```
memory_alloc(size: usize, align: usize, flags: u64) -> ptr
```

`size` は確保するバイト数です。

`align` は要求するアラインメントです。

`flags` には読み取り、書き込み、実行可否、ユーザー空間配置などの属性を指定します。

### memory_free

`memory_alloc` で確保した匿名メモリを解放します。

```
memory_free(addr: ptr, size: usize) -> isize
```

`addr` と `size` は確保時の領域に対応している必要があります。

不正な範囲、二重解放、未確保領域の解放はエラーにします。

### memory_map

Capabilityに基づくメモリマッピングを作成します。

```
memory_map(source_cap: cap_t, offset: u64, size: usize, prot: u64, flags: u64) -> ptr
```

`source_cap` はマッピング元を表します。

匿名マッピング、共有メモリ、将来のファイルページ、デバイスメモリなどを同じ入口で扱える設計にします。

`prot` は読み取り、書き込み、実行の保護属性です。

`flags` はprivate/shared、固定アドレス指定、遅延割り当てなどの属性です。

### memory_unmap

マッピング済みメモリを解除します。

```
memory_unmap(addr: ptr, size: usize) -> isize
```

指定範囲がページ境界に揃っていない場合はエラーにします。

### memory_protect

既存マッピングの保護属性を変更します。

```
memory_protect(addr: ptr, size: usize, prot: u64) -> isize
```

読み取り専用化、実行不可化などに使います。

元のCapabilityで許可されていない権限を追加してはいけません。

### memory_share

プロセス間共有メモリを作成、または既存領域から共有Capabilityを作成します。

```
memory_share(addr: ptr, size: usize, flags: u64) -> cap_t
```

返されたCapabilityはIPCなどで他プロセスへ渡せます。

大容量データをIPCメッセージ本体に載せる代わりに、この共有メモリを使います。

### memory_sync

共有メモリやマッピング済み領域の同期を要求します。

```
memory_sync(addr: ptr, size: usize, flags: u64) -> isize
```

将来のFS-backed mapping、GPU buffer、共有リングバッファなどの同期に使います。

`flags` にはflush、invalidate、writebackなどの同期種別を指定できます。

### 物理メモリ操作

物理アドレスの取得や物理ページのマッピングは、一般的な `memory_map` / `memory_share` とは別に扱います。

```
memory_phys_translate(target: pid_t, vaddr: ptr) -> u64
memory_phys_map(target: pid_t, phys: u64, size: usize, flags: u64) -> ptr
```

これらは `memory.phys.translate` / `memory.phys.map` capability を持つプロセスだけが呼び出せます。
さらに、他プロセスを対象にする場合は、そのプロセスへアクセスする権限も必要です。
カーネルは Service 権限だけではこれらを許可しません。

## IPC

IPC の詳細設計は [`docs/ipc.md`](ipc.md) を参照してください。

### ipc_create

IPC endpointを作成します。

```
ipc_create(flags: u64) -> cap_t
```

戻り値はendpoint capabilityです。

このCapabilityを持つプロセスだけが、対象endpointに対して送受信できます。

### ipc_send

非同期メッセージを送信します。

```
ipc_send(endpoint_cap: cap_t, msg_ptr: ptr, msg_len: usize, flags: u64) -> isize
```

`msg_ptr` はユーザー空間上のメッセージヘッダと短いpayloadを指します。

大容量データはメッセージ本体に載せず、`memory_share` による共有メモリCapabilityを使います。

### ipc_recv

IPC endpointからメッセージを受信します。

```
ipc_recv(endpoint_cap: cap_t, msg_ptr: ptr, msg_len: usize, flags: u64) -> isize
```

受信したメッセージを `msg_ptr` へ書き込みます。

メッセージが存在しない場合の挙動は `flags` により、ブロックまたは `EAGAIN` とします。

### ipc_call

同期RPCを実行します。

```
ipc_call(endpoint_cap: cap_t, req_ptr: ptr, req_len: usize, resp_ptr: ptr, resp_len: usize, flags: u64) -> isize
```

呼び出し元は要求を送信した後、対応する `ipc_reply` が返るまで待機します。

短い要求と短い応答は高速IPCのfast pathで処理できるようにします。

大容量データは共有メモリCapabilityで渡します。

### ipc_reply

`ipc_call` に対して応答します。

```
ipc_reply(reply_cap: cap_t, resp_ptr: ptr, resp_len: usize, flags: u64) -> isize
```

`reply_cap` は受信したcallに紐づく返信用Capabilityです。

関係のない相手へ任意に返信できてはいけません。

### ipc_wait

IPC endpointやIPC関連イベントを待機します。

```
ipc_wait(wait_ptr: ptr, wait_len: usize, result_ptr: ptr, flags: u64) -> isize
```

複数endpointの待機、call受信、send受信、completion待機などに使います。

FS、GPU、Display、Networkなどの常駐サービスは、このシステムコールを使って効率よく待機できます。

## Capability

### cap_clone

Capabilityを複製します。

```
cap_clone(cap: cap_t, flags: u64) -> cap_t
```

元のCapabilityと同等、またはそれ以下の権限を持つCapabilityを返します。

### cap_drop

Capabilityを破棄します。

```
cap_drop(cap: cap_t) -> isize
```

破棄後、そのhandleは無効になります。

ファイル、endpoint、event、共有メモリなどのリソース解放にも使えます。

### cap_transfer

Capabilityを他プロセスまたはIPCメッセージへ移譲します。

```
cap_transfer(target_cap: cap_t, cap: cap_t, flags: u64) -> isize
```

`target_cap` は転送先を表します。

実際の転送方法はIPCメッセージと組み合わせて使います。

### cap_query

Capabilityの種類と権限を取得します。

```
cap_query(cap: cap_t, info_ptr: ptr, info_len: usize) -> isize
```

`info_ptr` へCapability種別、許可操作、属性などを書き込みます。

### cap_restrict

Capabilityの権限を削った派生Capabilityを作ります。

```
cap_restrict(cap: cap_t, rights: u64, flags: u64) -> cap_t
```

元Capabilityより強い権限を作ってはいけません。

権限を追加しようとした場合は `EPERM` を返します。

## Event

### event_create

イベントオブジェクトを作成します。

```
event_create(flags: u64) -> cap_t
```

戻り値はevent capabilityです。

イベントはIPC completion、timer、GPU completion、FS completionなどの通知に使えます。

### event_wait

単一イベントを待機します。

```
event_wait(event_cap: cap_t, timeout_ns: u64, flags: u64) -> isize
```

`timeout_ns` は待機上限をナノ秒単位で指定します。

タイムアウトした場合は `ETIMEOUT` を返します。

### event_signal

イベントを通知状態にします。

```
event_signal(event_cap: cap_t, value: u64, flags: u64) -> isize
```

待機中のスレッドがあれば起床させます。

`value` は通知値として使えます。

### event_poll

複数イベントを待機します。

```
event_poll(events_ptr: ptr, event_count: usize, result_ptr: ptr, timeout_ns: u64, flags: u64) -> isize
```

複数のevent capabilityを同時に待機します。

GUI、FS、GPU、timer、IPC completionなどを同じ待機ループで扱うために使います。

## Time

### time_now

現在時刻または単調増加時刻を取得します。

```
time_now(clock_id: u64, out_ptr: ptr) -> isize
```

`clock_id` により取得する時計を指定します。

最低限、単調増加時計を提供します。

`out_ptr` には時刻構造体を書き込みます。

### sleep

現在のスレッドを指定時間だけ待機させます。

```
sleep(duration_ns: u64, flags: u64) -> isize
```

`duration_ns` は待機時間をナノ秒単位で指定します。

スケジューラは指定時間が経過するまで対象スレッドを実行可能状態から外します。

## I/O

### Write
```
write(str: &str) -> isize
```
シリアルコンソールへ文字列を書き込みます。

## Filesystem

Filesystem は最小カーネルの例外として残します。
高頻度のディスク入出力は cext やサービスに寄せる前提ですが、
起動初期化や基本的なファイルアクセスのために、以下の syscall は公開します。

### file_open

```
file_open(path: ptr, flags: u64) -> u64
```

### file_open_at

```
file_open_at(dirfd: i64, path: ptr, flags: u64, mode: u64) -> u64
```

### file_close

```
file_close(fd: u64) -> isize
```

### file_read

```
file_read(fd: u64, buf: ptr, len: usize) -> isize
```

### file_write

```
file_write(fd: u64, buf: ptr, len: usize) -> isize
```

### file_seek

```
file_seek(fd: u64, offset: i64, whence: u64) -> isize
```

### file_stat

```
file_stat(path: ptr, stat: ptr) -> isize
```

### file_stat_at

```
file_stat_at(dirfd: i64, path: ptr, stat: ptr, flags: u64) -> isize
```

### file_fstat

```
file_fstat(fd: u64, stat: ptr) -> isize
```

### file_read_dir

```
file_read_dir(fd: u64, buf: ptr, len: usize) -> isize
```

### file_create_dir

```
file_create_dir(path: ptr, mode: u64) -> isize
```

### file_remove

```
file_remove(path: ptr) -> isize
```

### file_rename

```
file_rename(old_dirfd: i64, old_path: ptr, new_dirfd: i64, new_path: ptr) -> isize
```

### file_sync

```
file_sync(fd: u64) -> isize
```

## 高速IPCの扱い

FS、GPU、Display、Networkなどの高頻度I/Oは、専用syscallではなく高速IPCを使います。

ただし、データ本体をIPCメッセージに載せてはいけません。IPCメッセージは制御命令、opcode、短い引数、Capability転送に使います。

大容量データは次の仕組みで扱います。

```
memory_share
memory_map
memory_sync
event_poll
ipc_call
ipc_reply
ipc_wait
```

## ABI安定性

この文書に記載されたシステムコールだけを公開ABIとします。

未記載のシステムコール番号が呼び出された場合、カーネルはpanicせず、未知のシステムコールとしてエラーを返します。

# IPC Design

`mnu` の IPC は、汎用メッセージバスではなく、同期 RPC を最速経路に置くための仕組みとして設計しています。

この文書は、現在の実装に合わせた IPC の動作と、固定領域の役割を説明します。

## 目的

IPC の最優先用途は次の通りです。

- `ipc_call` による短い同期 RPC
- `ipc_reply` による応答
- `ipc_wait` による受信待機

大きいデータは IPC メッセージ本体で運ばず、共有メモリやページ転送で渡します。

## 公開 syscall

現在の公開 ABI では、IPC 関連 syscall は次の 6 つです。

- `ipc_create(flags)`
- `ipc_send(endpoint, msg_ptr, msg_len)`
- `ipc_recv(msg_ptr, msg_len)`
- `ipc_call(endpoint, req_ptr, req_len, reply_ptr, reply_len)`
- `ipc_reply(endpoint, reply_ptr, reply_len)`
- `ipc_wait(msg_ptr, msg_len, blocking)`

`ipc_wait` の `blocking` 引数は、`0` のときは現在スレッドの受信待機、非 0 のときは endpoint handle を表します。

## endpoint

`ipc_create` は、現在スレッドに紐づく endpoint handle を返します。

この handle は世代番号付きで、スレッド再利用による誤配送を避けるために検証されます。

endpoint は次の用途を持ちます。

- 同期 RPC の宛先
- 受信待機の対象
- サービス間 rendezvous の識別子

## 固定領域

fast IPC は、各スレッドに固定でぶら下がる小さな領域を使います。

現在の実装では、これは `Thread` 内の `IpcFastState` です。

保持している情報は次の通りです。

- 待機中かどうか
- 待機していた CPU
- 受信済み request
- reply 待ちかどうか
- reply の書き戻し先
- reply の長さ
- 48 bytes 以下の短いメッセージ本体

この領域は UTBC 相当の役割を持ちますが、公開 ABI ではありません。

## fast path

fast path に乗る条件は次の通りです。

- メッセージ長が 48 bytes 以下
- 送信先が待機中
- 送受信が同一 CPU 上
- capability 転送なし
- page 転送なし
- timeout なし

fast path では、次のように振る舞います。

1. client が `ipc_call` する
2. server が待機中なら request を固定領域へ直接格納する
3. client を reply 待ちにする
4. server を直接起床させる
5. scheduler をなるべく経由せずに切り替える

`ipc_reply` でも同様に、reply 待ちの client が同一 CPU で待機していれば、reply buffer へ直接書き戻します。

## slow path

次のものは slow path に落とします。

- 長いメッセージ
- capability 転送
- ページ転送
- timeout
- cross-core

slow path は mailbox を使う既存経路です。

これは正しい挙動を優先する経路であり、fast path のような超低遅延は狙っていません。

## reply / wait の推奨パターン

現在の公開 syscall では、`ipc_reply_recv` はまだ独立 syscall ではありません。

推奨パターンは次の通りです。

- server は `ipc_wait` で request を受ける
- server は `ipc_reply` で応答する
- server が次の request を待つときは、再度 `ipc_wait` を呼ぶ

カーネル内部には reply 直後に次の受信へ移るための helper がありますが、これは内部実装です。

## 大きいファイルの扱い

巨大なデータは IPC に載せません。

ファイル本体や bulk buffer は次の経路で渡します。

- 共有メモリ
- ページ転送
- ファイルシステムの read path

IPC は制御面だけを担当します。

そのため、巨大ファイルの実効速度は IPC の速さではなく、実際の read path とメモリコピー、ページマップ、ストレージに支配されます。

## テスト

`core.service`で、IPC の最小デモとして ping/pong をします。

このサービスは endpoint を作成し、短い `ping` を受けたら `pong` を返します。

同時に、同一プロセス内の client thread から `ipc_call` を投げて、fast path の動作確認も行います。

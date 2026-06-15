# Cext - Core extensions for mnu

mnuカーネルは、Cextと呼ばれるカーネル拡張機能を提供しています。
Cextは、mnuカーネルのコア機能を拡張するためのモジュールであり、ユーザーが独自の機能を追加することができます。

Cextには主にbuilt-in cextとmodule cextの2種類があります。
built-in cextは、mnuカーネルのビルド時に組み込まれるcextであり、カーネルの基本的な機能を提供します。
module cextは、ユーザーが動的にロードできるcextであり、必要に応じてロードされたりアンロードされたりします。

カーネルは、次のようなものを提供します。

- プロセス管理
- スレッド管理
- メモリ管理
- スケジューリング
- IPC
- Capability管理
- 割り込み処理
- 例外処理
- システムコール
- カーネルログ

一方で、ファイルシステム、ストレージ、GPU、USB、ネットワーク、入力デバイスなどはCextとして実装します。
これにより、mnuはカーネル本体を小さく保ちながら、必要な機能だけを追加できる構造になります。

## built-in cext

built-in cextは、mnuカーネルのビルド時に組み込まれるCextです。
起動直後から利用可能であり、外部ファイルを読み込む前に必要な機能を提供します。
built-in cextは、主に起動に必要な最小限の機能に使います。

代表的なbuilt-in cextは次のとおりです。

- fs.cext
- disk.cext

fs.cextは、initfsやrootfsを扱うためのファイルシステム機能を提供します。
外部のserviceやmodule cextを読み込むためには、最初にファイルシステムが必要になります。そのため、fs.cextはbuilt-in cextとして扱います。
disk.cextは、fs.cextが実際のストレージやinitfsにアクセスするための機能を提供します。
built-in cextは、カーネル本体と同時に読み込まれるため、動的にアンロードされません。
また、起動に必須なbuilt-in cextが失敗した場合、カーネルは通常の起動を継続できません。
その際は、カーネルはログを出力してハングアップします。

## module cext

module cextは、起動後に必要に応じて読み込まれるCextです。
module cextは、ファイルシステム上に配置され、core.serviceまたは他の管理サービスによってロードされます。
module cextは、次のような機能に使います。

- gpu.cext
- usb.cext
- net.cext
- audio.cext
- input.cext
- 追加のfilesystem cext
- 追加のstorage driver cext

module cextは、起動に必須ではない機能を分離するために使用します。
これにより、特定のデバイスドライバや機能が失敗しても、カーネル全体が停止しない構造にできます。
module cextは、ロード時に署名、manifest、Capability要求を検証されます。
許可されていないCapabilityを要求するmodule cextはロードされません。
また、module cextのELFはCext専用の仮想アドレス範囲にのみ配置されます。
この範囲外の `PT_LOAD` は拒否され、既存のカーネルマッピングや他のモジュール領域に対する上書きは行われません。
ロード先のページが既にマップ済みの場合も、カーネルはそれを再利用せずエラーとして扱います。

## Cextとカーネルの境界

Cextはカーネルを拡張する仕組みですが、カーネル本体の責務を置き換えるものではありません。

次の機能はカーネル本体に属します。

- スケジューラ
- プロセス管理
- スレッド管理
- メモリ管理
- ページテーブル管理
- システムコール
- IPCの基本機構
- Capability管理
- `memory.phys.map` / `memory.phys.translate` のような物理メモリ系 capability の最終判定
- 割り込みの基本処理
- 例外処理
- カーネルログ

これらは、OSの実行基盤そのものです。

そのため、Cextとして外部化すると、Cextの失敗によってカーネルの隔離、権限検査、実行制御が壊れる可能性があります。

Cextに置くべきものは、カーネルの実行基盤ではなく、デバイスやサブシステムの実装です。

## cext.toml

各Cextには、cext.tomlを配置します。
cext.tomlには、そのCextが何を実装しているか、何に依存しているか、どのCapabilityを必要とするかを記述します。
cext.tomlは、Cextを安全にロードするためのbuild-time manifest入力です。
ビルド時に集約され、カーネルは生成済みの manifest を読みます。runtime で TOML を解釈しません。
基本的な構成は次のとおりです。

```toml
[cext]
id = "org.mochios.fs"
name = "fs"
version = "0.1.0"
entry = "builtin"
type = "filesystem"
builtin = true

[implements]
kind = "filesystem"
interfaces = [
  "vfs",
  "mount",
  "file_io",
  "directory_io"
]

[provides]
services = [
  "fs"
]

devices = []

filesystems = [
  "ext2"
]

[depends]
cexts = [
  "org.mochios.storage"
]

services = []

kernel = [
  "ipc",
  "memory_share",
  "capability",
  "event"
]

optional = []

[boot]
stage = "early"
order = 20
required = true
restart = "panic"
```

## cextセクション

cextセクションには、Cext自体の基本情報を記述します。

- id: Cextを一意に識別するID
- name: 人間が読むための短い名前
- version: Cextのバージョン
- entry: 実際にロードするCextバイナリ
- type: Cextの大分類
- builtin: built-in cextかどうか

typeには、次のような値を使用します。

- filesystem
- storage
- gpu
- usb
- network
- input
- audio
- platform
- debug
- misc

## implementsセクション

implementsセクションには、そのCextが何を実装しているかを記述します。

kindは、実装している機能の種類です。

interfacesは、Cextが提供する具体的なインターフェースです。

filesystem cextでは、次のようなinterfacesを使用します。

- vfs
- mount
- file_io
- directory_io
- metadata
- permissions
- mmap_file

storage cextでは、次のようなinterfacesを使用します。

- block_read
- block_write
- flush
- partition_scan
- device_discovery

gpu cextでは、次のようなinterfacesを使用します。

- framebuffer
- mode_set
- buffer_alloc
- buffer_present
- gpu_command_queue

input cextでは、次のようなinterfacesを使用します。

- keyboard
- mouse
- touch
- gamepad
- input_events

network cextでは、次のようなinterfacesを使用します。

- ethernet
- packet_rx
- packet_tx
- mac_address
- link_status

usb cextでは、次のようなinterfacesを使用します。

- usb_host
- device_enumeration
- endpoint_control
- interrupt_transfer
- bulk_transfer

audio cextでは、次のようなinterfacesを使用します。

- pcm_output
- pcm_input
- volume
- device_select

## providesセクション

providesセクションには、そのCextが外部に提供するものを記述します。

- services: 他のserviceやCextから参照されるサービス名
- devices: Cextが公開するデバイス
- filesystems: 対応するファイルシステム名
- protocols: 対応する通信プロトコルやIPCプロトコル

例として、fs.cextなら次のような内容になります。

- services: fs
- devices: なし
- filesystems: ext2
- protocols: vfs-v1

## dependsセクション

dependsセクションには、そのCextが依存するものを記述します。

- cexts: 先にロードされている必要があるCext
- services: 依存するservice
- kernel: 必要なカーネル機能

依存関係が満たされていないCextはロードされません。

## bootセクション

bootセクションには、Cextの起動順と失敗時の扱いを記述します。

- stage: Cextをロードする起動段階
- order: 同じstage内での起動順
- required: そのCextが必須かどうか
- restart: Cextが停止したときの扱い

stageには、次の値を使用します。

- early
- core
- normal
- late

restartには、次の値を使用します。

- never
- restart
- isolate

built-in cextや起動に必須のCextでは、requiredをtrueにします。

起動後に追加されるmodule cextでは、通常requiredをfalseにします。

## Cextの失敗処理

Cextが失敗した場合の扱いは、boot.restartによって決まります。

- restart = neverの場合、Cextは再起動されません
- restart = restartの場合、可能であればCextを再起動します
- restart = isolateの場合、Cextを隔離し、他のCextやserviceへの影響を止めます

起動に必須のCextでは、失敗時にpanicすることがあります。

一方で、GPU、USB、ネットワーク、オーディオなどのCextは、失敗してもカーネル全体を停止させない設計にします。

## built-in cextの方針

mnuでは、built-in cextを増やしすぎない方針を取ります。
built-in cextが増えすぎると、カーネルのビルドに強く結合し、動的に拡張できるというCextの利点が弱くなります。
built-in cextにするべきものは、起動の根になる機能だけです。
今の段階では、次のCextをbuilt-inとして扱います。

- fs.cext
- disk.cext

それ以外のCextは、原則としてmodule cextとして扱います。

## module cextの方針

module cextは、起動後に必要なものだけをロードします。
module cextは、署名とCapabilityによって制限されます。
Cextが要求したCapabilityが、そのCextの署名、manifest、ユーザー設定、システムポリシーに反する場合、そのCextはロードされません。
ただし、Cextはカーネルと同じ信頼境界に置かれるため、無制限に権限を与えてはいけません。

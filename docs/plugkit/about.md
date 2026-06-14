# PlugKit

PlugKitはmnuカーネルにおいて、ユーザー空間で動作するドライバを作成するためのフレームワークです。
PlugKitを使用することで、ユーザー空間でドライバを実装し、カーネル空間のコードを最小限に保ちながら、デバイスドライバを開発できます。

## 提供する機能

PlugKitは、mnuのデバイスドライバを実装するための共通モデル、API、ライフサイクル、リソース管理、デバイスツリー、ドライバ照合機構を提供します。
mnuのドライバは、PlugKit上のPlugKitDriverとして実装されます。
PlugKitDriverは、特定のデバイスクラスやプロトコルに対応するドライバを表す共通モデルです。

PlugKitDriverは、次の処理を担当します。

- デバイスの検出結果に対する照合
- デバイスの初期化
- 必要なリソースの取得
- MMIO、IRQ、DMAなどの操作
- デバイスイベントの処理
- 上位serviceへ提供するinterfaceの登録
- デバイス停止時のクリーンアップ

PlugKitは、PlugKitDriverがカーネル内部構造へ直接アクセスしなくてもよいように、必要なAPIを提供します。

PlugKitDriverは、カーネルからケーパビリティに基づいて渡されたhandleを通じてデバイスやリソースを操作します。
これにより、ユーザー空間ドライバであっても、許可されていないデバイスやリソースへ直接アクセスできないようにします。

PlugKitDriverの配置と検出はserviceが担当します。
serviceはパッケージを配置し、`about.toml` を読み、kernelのPlugKit登録APIへmanifestを渡します。
kernelは特定のディレクトリを特別扱いせず、serviceから渡されるmanifestとパッケージ情報を元にPlugKitDriverを管理します。

PlugKitDriverパッケージの形式は以下のとおりです。

```
/foo.driver
├─ about.toml
└─ entry.elf
```

about.tomlは、PlugKitDriverのメタデータを記述するファイルです。
entry.elfは、PlugKitDriverの実装を含むELF形式のバイナリファイルです。

配置先のディレクトリやパッケージ探索規則はserviceが決めます。kernelは場所を前提にしません。

## メタデータ
about.tomlには、PlugKitDriverのメタデータを記述します。
以下は、about.tomlの例です。

```toml
[driver]
id = "com.example.net"
name = "VirtIO Network Driver"
version = "0.1.0"
description = "A driver for VirtIO network devices."
developer = "Example"
entry = "entry.elf"

[plugkit]
api = "1"
driver_class = "network"

[[match]]
bus = "pci"
vendor_id = "0x1af4"
device_id = "0x1000"

[capabilities]
requires = [
    "device.pci.config",
    "device.mmio.map",
    "irq.bind",
    "dma.map",
    "ipc.server"
]

[provides] 
interfaces = [ "net.device" ]

```

- `[driver]`セクションは、PlugKitDriverの基本情報を記述します。
- `[plugkit]`セクションは、PlugKitに関する情報を記述します。
- `[match]`セクションは、PlugKitDriverが対応するデバイスの検出条件を記述します。
- `[capabilities]`セクションは、PlugKitDriverが必要とするケーパビリティを記述します。
- `[provides]`セクションは、PlugKitDriverが提供するインターフェースを記述します。

それぞれのキーの意味は以下のとおりです。

- `id`: PlugKitDriverの一意な識別子
- `name`: PlugKitDriverの表示名
- `version`: PlugKitDriverのバージョン
- `description`: PlugKitDriverの説明
- `developer`: PlugKitDriverの開発者/組織
- `entry`: PlugKitDriverの実装が含まれるELFファイルの名前
- `api`: PlugKitのAPIバージョン
- `driver_class`: PlugKitDriverのクラス（任意の文字列で、ドライバのカテゴリを表す）
- `bus`: デバイスのバス（例: "pci", "usb", "virtio"など）
- `vendor_id`: デバイスのベンダーID（16進数形式）
- `device_id`: デバイスのデバイスID（16進数形式）
- `requires`: PlugKitDriverが必要とするケーパビリティのリスト
- `interfaces`: PlugKitDriverが提供するインターフェースのリスト

`driver_class`は、ドライバのカテゴリを表す任意の文字列です。次のものを利用することが推奨されますが、必須ではありません。

- `network`: ネットワークデバイスドライバ
- `storage`: ストレージデバイスドライバ
- `input`: 入力デバイスドライバ
- `gpu`: グラフィックデバイスドライバ
- `audio`: オーディオデバイスドライバ
- `usb`: USBデバイスドライバ
- `virtio`: VirtIOデバイスドライバ
- `filesystem`: ファイルシステムドライバ
- `block`: ブロックデバイスドライバ
- `character`: キャラクタデバイスドライバ
- `display`: ディスプレイドライバ
- `input`: 入力ドライバ
- `other`: 上記以外のドライバ

## 実行モデル

PlugKitDriverはユーザー空間プロセスとして起動します。
serviceは、必要な場所に配置されたPlugKitDriverパッケージを検出し、manifestを読み取り、対象デバイスに対応するPlugKitDriverを選びます。

PlugKitは、対象デバイスに対応するPlugKitDriverを選び、必要なhandleを渡して起動します。

PlugKitDriverは、PlugKit APIを通してデバイス情報、MMIO、IRQ、DMAなどを操作します。
PlugKitDriverが異常終了した場合、PlugKitはそのドライバを停止済みとして扱い、貸与していたhandleを回収します。

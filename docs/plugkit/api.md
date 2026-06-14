# PlugKit API

この文書は、Rustクレート `plugkit` が提供するAPIを定義します。

`plugkit` は、mnuのPlugKitDriverをRustで実装するためのライブラリです。

PlugKitDriverは、PlugKitが提供するAPIを通して、デバイス情報の取得、リソース操作、イベント待機、interface登録、ログ出力などを行います。

## 基本方針

`plugkit` は、PlugKitDriverを書くために必要な高レベルAPIを提供します。

PlugKitDriverは、カーネル内部構造へ直接アクセスしません。

PlugKitDriverは、PlugKitから渡されたhandleを通してデバイスやリソースを操作します。

`plugkit` は、次のAPI群を提供します。

- ドライバライフサイクルAPI
- デバイス情報API
- リソースAPI
- MMIO API
- IRQ API
- DMA API
- PCI config API
- interface API
- event API
- logging API
- error API

## PlugKitDriver

`PlugKitDriver` は、PlugKitDriverの基本ライフサイクルを表すtraitです。

```rust
pub trait PlugKitDriver {
    fn probe(device: &PlugKitDevice) -> ProbeResult;

    fn start(
        device: PlugKitDevice,
        resources: PlugKitResources,
    ) -> PlugKitResult<()>;

    fn stop(device: PlugKitDevice) -> PlugKitResult<()>;
}
```

### probe

`probe` は、対象デバイスをこのPlugKitDriverが扱えるかを判定します。

```rust
fn probe(device: &PlugKitDevice) -> ProbeResult;
```

PlugKitDriverは、`PlugKitDevice` からデバイス情報を取得し、自分が対応するデバイスかどうかを判定します。

### start

`start` は、対象デバイスを初期化します。

```rust
fn start(
    device: PlugKitDevice,
    resources: PlugKitResources,
) -> PlugKitResult<()>;
```

PlugKitDriverは、`PlugKitResources` を通してMMIO、IRQ、DMAなどのリソースを取得します。

初期化に成功した場合、必要に応じて上位service向けのinterfaceを登録します。

### stop

`stop` は、対象デバイスを停止します。

```rust
fn stop(device: PlugKitDevice) -> PlugKitResult<()>;
```

PlugKitDriverは、登録したinterfaceを解除し、デバイスを停止可能な状態にします。

## ProbeResult

`ProbeResult` は、`probe` の結果を表します。

```rust
pub enum ProbeResult {
    Reject,
    Match { score: u32 },
}
```

`Reject` は、このPlugKitDriverでは対象デバイスを扱えないことを表します。

`Match` は、このPlugKitDriverが対象デバイスを扱えることを表します。

`score` は、複数のPlugKitDriverが同じデバイスに対応できる場合の優先度です。値が高いほど優先されます。

## PlugKitDevice

`PlugKitDevice` は、PlugKitが管理するデバイスを表します。

```rust
pub struct PlugKitDevice;
```

`PlugKitDevice` は、次の情報取得APIを提供します。

```rust
impl PlugKitDevice {
    pub fn id(&self) -> DeviceId;
    pub fn path(&self) -> PlugKitResult<DevicePath>;
    pub fn name(&self) -> PlugKitResult<DeviceName>;
    pub fn bus(&self) -> DeviceBus;
    pub fn class(&self) -> DeviceClass;
    pub fn vendor_id(&self) -> Option<u32>;
    pub fn device_id(&self) -> Option<u32>;
    pub fn subsystem_vendor_id(&self) -> Option<u32>;
    pub fn subsystem_device_id(&self) -> Option<u32>;
    pub fn revision(&self) -> Option<u8>;
    pub fn property(&self, key: &str) -> PlugKitResult<Option<DeviceProperty>>;
}
```

`PlugKitDevice` は、デバイスの検出情報を取得するために使用します。

PlugKitDriverは、`PlugKitDevice` を通して対象デバイスの種類、バス、ID、class、追加propertyを確認します。

## DeviceId

`DeviceId` は、PlugKitが管理するデバイスを識別するIDです。

```rust
pub struct DeviceId;
```

## DevicePath

`DevicePath` は、デバイスツリー上のパスを表します。

```rust
pub struct DevicePath;
```

例:

```text
/platform/ps2-controller0
/pci0/00:02.0
/usb0/hub0/keyboard0
```

## DeviceName

`DeviceName` は、デバイスの表示名を表します。

```rust
pub struct DeviceName;
```

## DeviceBus

`DeviceBus` は、デバイスが属するバスを表します。

```rust
pub enum DeviceBus {
    Platform,
    Pci,
    Usb,
    Virtio,
    Other,
}
```

## DeviceClass

`DeviceClass`は、デバイスの種類を表します。

```rust
pub enum DeviceClass {
    Network,
    Storage,
    Block,
    Character,
    Input,
    Gpu,
    Display,
    Audio,
    Usb,
    Virtio,
    Bus,
    Other,
}
```

## DeviceProperty

`DeviceProperty`は、デバイスに付随する追加情報を表します。

```rust
pub enum DeviceProperty {
    Bool(bool),
    U32(u32),
    U64(u64),
    String(DeviceString),
    Bytes(DeviceBytes),
}
```

## PlugKitResources

`PlugKitResources`は、PlugKitDriverに渡されたリソース集合を表します。

```rust
pub struct PlugKitResources;
```

`PlugKitResources`は、次のAPIを提供します。

```rust
impl PlugKitResources {
    pub fn mmio_count(&self) -> usize;

    pub fn irq_count(&self) -> usize;

    pub fn dma_supported(&self) -> bool;

    pub fn has_pci_config(&self) -> bool;

    pub fn map_mmio(&self, index: usize) -> PlugKitResult<Mmio>;

    pub fn bind_irq(&self, index: usize) -> PlugKitResult<Irq>;

    pub fn alloc_dma(&self, size: usize) -> PlugKitResult<DmaBuffer>;

    pub fn pci_config(&self) -> PlugKitResult<PciConfig>;
}
```

PlugKitDriverは、物理アドレスやIRQ番号を直接扱いません。

MMIO、IRQ、DMA、PCI configなどは、すべてPlugKitが提供する型を通して操作します。

## Mmio

`Mmio`は、PlugKitDriverに許可されたMMIO領域を表します。

```rust
pub struct Mmio;
```

`Mmio`は、次のAPIを提供します。

```rust
impl Mmio {
    pub fn len(&self) -> usize;
    pub fn read_u8(&self, offset: usize) -> PlugKitResult<u8>;
    pub fn read_u16(&self, offset: usize) -> PlugKitResult<u16>;
    pub fn read_u32(&self, offset: usize) -> PlugKitResult<u32>;
    pub fn read_u64(&self, offset: usize) -> PlugKitResult<u64>;
    pub fn write_u8(&self, offset: usize, value: u8) -> PlugKitResult<()>;
    pub fn write_u16(&self, offset: usize, value: u16) -> PlugKitResult<()>;
    pub fn write_u32(&self, offset: usize, value: u32) -> PlugKitResult<()>;
    pub fn write_u64(&self, offset: usize, value: u64) -> PlugKitResult<()>;
}
```

`Mmio`は、デバイスのレジスタアクセスに使用します。

## Irq

`Irq` は、PlugKitDriverに割り当てられたIRQイベントを表します。

```rust
pub struct Irq;
```

`Irq` は、次のAPIを提供します。

```rust
impl Irq {
    pub fn wait(&self) -> PlugKitResult<IrqEvent>;

    pub fn ack(&self) -> PlugKitResult<()>;
}
```

`wait`は、IRQイベントを待機します。また、`ack`は、IRQイベントの処理完了をPlugKitへ通知します。

## IrqEvent

`IrqEvent` は、PlugKitから配送されたIRQイベントを表します。

```rust
pub struct IrqEvent {
    pub sequence: u64,
}
```

## DmaBuffer

`DmaBuffer` は、DMA用のバッファを表します。

```rust
pub struct DmaBuffer;
```

`DmaBuffer` は、次のAPIを提供します。

```rust
impl DmaBuffer {
    pub fn len(&self) -> usize;
    pub fn device_addr(&self) -> u64;
    pub fn as_slice(&self) -> &[u8];
    pub fn as_mut_slice(&mut self) -> &mut [u8];
    pub fn sync_for_device(&self) -> PlugKitResult<()>;
    pub fn sync_for_cpu(&self) -> PlugKitResult<()>;
}
```

- `device_addr` は、デバイスへ渡すDMAアドレスを表します。
- `sync_for_device` は、CPU側で書き込んだ内容をデバイスから見える状態にします。
- `sync_for_cpu` は、デバイス側で書き込まれた内容をCPUから見える状態にします。

## PciConfig

`PciConfig` は、PCI config spaceへのアクセスを提供します。

```rust
pub struct PciConfig;
```

`PciConfig` は、次のAPIを提供します。

```rust
impl PciConfig {
    pub fn read_u8(&self, offset: usize) -> PlugKitResult<u8>;
    pub fn read_u16(&self, offset: usize) -> PlugKitResult<u16>;
    pub fn read_u32(&self, offset: usize) -> PlugKitResult<u32>;
    pub fn write_u8(&self, offset: usize, value: u8) -> PlugKitResult<()>;
    pub fn write_u16(&self, offset: usize, value: u16) -> PlugKitResult<()>;
    pub fn write_u32(&self, offset: usize, value: u32) -> PlugKitResult<()>;
}
```

`PciConfig`は、PCIデバイスの設定空間を読み書きするために使用します。

## Interface

PlugKitDriverは、初期化に成功したあと、上位serviceへinterfaceを公開できます。

```rust
pub struct InterfaceHandle;
```

interface関連APIは次の通りです。

```rust
pub fn register_interface(name: &str) -> PlugKitResult<InterfaceHandle>;

pub fn unregister_interface(name: &str) -> PlugKitResult<()>;
```

例:

```rust
plugkit::register_interface("net.device")?;
```

interface名は、PlugKitDriverのメタデータに宣言されている必要があります。

## PlugKitEvent

`PlugKitEvent` は、PlugKitDriverからPlugKitへ通知するイベントを表します。

```rust
pub enum PlugKitEvent {
    DeviceReady,
    DeviceStopped,
    LinkUp,
    LinkDown,
    MediaChanged,
    Error { code: u32 },
}
```

event関連APIは次の通りです。

```rust
pub fn emit_event(event: PlugKitEvent) -> PlugKitResult<()>;
```

PlugKitDriverは、デバイス状態の変化やエラーをPlugKitへ通知できます。

## Logging

PlugKitDriverは、PlugKitのログAPIを使用できます。

```rust
pub fn log_info(message: &str);

pub fn log_warn(message: &str);

pub fn log_error(message: &str);
```

ログは、PlugKitを通してmnuのログ機構へ送られます。

## PlugKitResult

`PlugKitResult`は、PlugKit APIの戻り値に使用するResult型です。

```rust
pub type PlugKitResult<T> = Result<T, PlugKitError>;
```

## PlugKitError

`PlugKitError`は、PlugKit APIで発生するエラーを表します。

```rust
pub enum PlugKitError {
    InvalidHandle,
    PermissionDenied,
    NotSupported,
    NoDevice,
    Busy,
    OutOfMemory,
    IoError,
    InvalidOffset,
    InvalidSize,
    Interrupted,
    Unknown,
}
```

- `InvalidHandle` は、無効なhandleを表します。
- `PermissionDenied` は、必要なケーパビリティがないことを表します。
- `NotSupported` は、対象操作がサポートされていないことを表します。
- `NoDevice` は、対象デバイスが存在しない、または削除済みであることを表します。
- `Busy` は、対象リソースが使用中であることを表します。
- `OutOfMemory` は、メモリ確保に失敗したことを表します。
- `IoError` は、デバイスI/Oの失敗を表します。
- `InvalidOffset` は、不正なオフセットを表します。
- `InvalidSize` は、不正なサイズを表します。
- `Interrupted` は、待機中の操作が中断されたことを表します。
- `Unknown` は、分類できないエラーを表します。

## Driver macro

PlugKitDriverは、crate rootでdriver登録用macroを呼び出します。

```rust
plugkit::driver!(MyDriver);
```

このmacroは、PlugKitDriverをPlugKit runtimeへ公開するために使用します。
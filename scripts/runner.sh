#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT_DIR}/target/uefi"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
RUN_ID="$(date +%s)-$$"
RUN_DIR="${TARGET_DIR}/run-${RUN_ID}"
ESP_DIR="${RUN_DIR}/esp"
ESP_IMG="${RUN_DIR}/esp.img"
INITFS_STAGE="${RUN_DIR}/initfs-root"
ROOTFS_STAGE="${RUN_DIR}/rootfs-root"
OVMF_VARS="${OVMF_VARS:-${RUN_DIR}/OVMF_VARS_4M.fd}"

mkdir -p "${TARGET_DIR}" "${ESP_DIR}/EFI/BOOT" "${INITFS_STAGE}" "${ROOTFS_STAGE}/config"

echo "[build] kernel"
RUSTC_BOOTSTRAP=1 cargo build --locked --release --target x86_64-unknown-none --features kernel-bin --manifest-path "${ROOT_DIR}/Cargo.toml"

echo "[build] userland"
RUSTFLAGS="-C link-arg=--image-base=0x10000" \
    cargo build --locked --release --target x86_64-unknown-none --manifest-path "${ROOT_DIR}/examples/user/Cargo.toml"

echo "[build] bootloader"
cargo build --locked --release --target x86_64-unknown-uefi --manifest-path "${ROOT_DIR}/examples/boot/Cargo.toml"

KERNEL_BIN="${ROOT_DIR}/target/x86_64-unknown-none/release/kernel"
USER_BIN="${ROOT_DIR}/examples/user/target/x86_64-unknown-none/release/user"
BOOT_BIN="$(find "${ROOT_DIR}/examples/boot/target/x86_64-unknown-uefi/release" -maxdepth 1 -type f \( -name 'boot' -o -name 'boot.efi' \) | head -n 1)"

if [[ ! -f "${KERNEL_BIN}" ]]; then
    echo "kernel binary not found: ${KERNEL_BIN}" >&2
    exit 1
fi
if [[ ! -f "${USER_BIN}" ]]; then
    echo "user binary not found: ${USER_BIN}" >&2
    exit 1
fi
if [[ -z "${BOOT_BIN}" || ! -f "${BOOT_BIN}" ]]; then
    echo "bootloader binary not found" >&2
    exit 1
fi

rm -rf "${ESP_DIR}" "${INITFS_STAGE}" "${ROOTFS_STAGE}"
mkdir -p "${ESP_DIR}/EFI/BOOT" "${INITFS_STAGE}" "${ROOTFS_STAGE}/config"

install -m 0644 "${KERNEL_BIN}" "${ESP_DIR}/kernel"
install -m 0644 "${BOOT_BIN}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI"
install -m 0755 "${USER_BIN}" "${INITFS_STAGE}/core.service"
install -m 0755 "${USER_BIN}" "${INITFS_STAGE}/hello.bin"
install -m 0644 "${ROOT_DIR}/examples/fs/hello.txt" "${ROOTFS_STAGE}/hello.txt"
install -m 0644 "${ROOT_DIR}/examples/fs/config/kernel.conf" "${ROOTFS_STAGE}/config/kernel.conf"

truncate -s 16M "${TARGET_DIR}/initfs.img"
truncate -s 16M "${TARGET_DIR}/rootfs.img"
mke2fs -q -t ext2 -b 1024 -d "${INITFS_STAGE}" -F "${TARGET_DIR}/initfs.img"
mke2fs -q -t ext2 -b 1024 -d "${ROOTFS_STAGE}" -F "${TARGET_DIR}/rootfs.img"

install -m 0644 "${TARGET_DIR}/initfs.img" "${ESP_DIR}/initfs.img"
install -m 0644 "${TARGET_DIR}/rootfs.img" "${ESP_DIR}/rootfs.img"

truncate -s 64M "${ESP_IMG}"
mkfs.fat -F 32 -n EFI "${ESP_IMG}"
MTOOLS_SKIP_CHECK=1 mmd -i "${ESP_IMG}" ::/EFI ::/EFI/BOOT
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/kernel" ::/kernel
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/initfs.img" ::/initfs
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/rootfs.img" ::/rootfs
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI

if [[ ! -f "${OVMF_VARS}" ]]; then
    cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS}"
fi

QEMU_ARGS=(
    -machine q35
    -m 512M
    -smp 4
    -cpu qemu64
    -serial stdio
    -display none
    -monitor none
    -no-reboot
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
    -drive "if=pflash,format=raw,file=${OVMF_VARS}"
    -drive "format=raw,file=${ESP_IMG}"
)

if [[ "${DEBUG:-0}" != "0" ]]; then
    QEMU_ARGS+=(-s -S)
fi

SERIAL_LOG="${TARGET_DIR}/serial.log"
rm -f "${SERIAL_LOG}"

echo "[run] qemu + userland self-test"

coproc QEMU_PROC {
    qemu-system-x86_64 "${QEMU_ARGS[@]}" 2>&1
}

QEMU_PID="${QEMU_PROC_PID}"
PASS_FOUND=0

cleanup() {
    kill "${QEMU_PID}" 2>/dev/null || true
    wait "${QEMU_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 600); do
    while IFS= read -r -t 0.01 line <&"${QEMU_PROC[0]}"; do
        printf '%s\n' "$line"

        if [[ "$line" == *"USERLAND SELF-TEST PASS"* ]]; then
            PASS_FOUND=1
            break
        fi
    done

    if [[ "${PASS_FOUND}" -eq 1 ]]; then
        break
    fi

    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        break
    fi

    sleep 0.1
done

if [[ "${PASS_FOUND}" -ne 1 ]]; then
    echo "userland self-test did not report PASS" >&2
    exit 1
fi

kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
trap - EXIT

echo "[run] userland self-test passed"
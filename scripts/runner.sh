#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TARGET_DIR="${ROOT_DIR}/target/uefi"

KERNEL_TARGET_NAME="x86_64-unknown-none"
USER_TARGET_NAME="x86_64-unknown-none"
KERNEL_FEATURES="${MNU_KERNEL_FEATURES:-kernel-bin}"

USER_BUILD_DIR="${TARGET_DIR}/user-build"
BOOT_BUILD_DIR="${TARGET_DIR}/boot-build"
PLUGKIT_BUILD_DIR="${TARGET_DIR}/plugkit-build"
CEXT_BUNDLES_DIR="${MNU_CEXT_BUNDLES_DIR:-}"

OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

RUN_ID="$(date +%s)-$$"
RUN_DIR="${TARGET_DIR}/run-${RUN_ID}"
ESP_DIR="${RUN_DIR}/esp"
ESP_IMG="${RUN_DIR}/esp.img"
INITFS_STAGE="${RUN_DIR}/initfs-root"
ROOTFS_STAGE="${RUN_DIR}/rootfs-root"
OVMF_VARS="${OVMF_VARS:-${RUN_DIR}/OVMF_VARS_4M.fd}"

SERIAL_LOG="${TARGET_DIR}/serial.log"

die() {
    echo "fatal: $*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

need_file() {
    [[ -f "$1" ]] || die "required file not found: $1"
}

need_dir() {
    [[ -d "$1" ]] || die "required directory not found: $1"
}

stage_cext_bundles() {
    [[ -n "${CEXT_BUNDLES_DIR}" ]] \
        || die "MNU_CEXT_BUNDLES_DIR must name a directory containing boot cext bundles"
    need_dir "${CEXT_BUNDLES_DIR}"

    local count=0
    while IFS= read -r -d '' bundle_dir; do
        need_file "${bundle_dir}/manifest.toml"
        need_file "${bundle_dir}/entry"
        cp -a "${bundle_dir}" "${INITFS_STAGE}/$(basename "${bundle_dir}")"
        count=$((count + 1))
    done < <(find "${CEXT_BUNDLES_DIR}" -mindepth 1 -maxdepth 1 -type d -name '*.cext' -print0)

    [[ "${count}" -gt 0 ]] || die "no cext bundles found in ${CEXT_BUNDLES_DIR}"
}

need_cmd cargo
need_cmd cp
need_cmd find
need_cmd grep
need_cmd perl
need_cmd openssl
need_cmd qemu-system-x86_64
need_cmd mke2fs
need_cmd mkfs.fat
need_cmd mmd
need_cmd mcopy
need_cmd readelf
need_cmd strings
need_cmd stat
need_cmd tee

need_file "${OVMF_CODE}"
need_file "${OVMF_VARS_TEMPLATE}"
need_file "${ROOT_DIR}/Cargo.toml"
need_file "${ROOT_DIR}/examples/user/Cargo.toml"
need_file "${ROOT_DIR}/examples/user/linker.ld"
need_file "${ROOT_DIR}/examples/boot/Cargo.toml"
need_file "${ROOT_DIR}/examples/plugkit/test/Cargo.toml"
need_file "${ROOT_DIR}/examples/plugkit/test/about.toml"
need_file "${ROOT_DIR}/scripts/rootfs.sh"
need_file "${ROOT_DIR}/scripts/signature_db.pl"

mkdir -p "${TARGET_DIR}" "${ESP_DIR}/EFI/BOOT" "${INITFS_STAGE}"

./scripts/generate_testdata.pl

echo "[build] kernel"
cargo build \
    --release \
    --target "${KERNEL_TARGET_NAME}" \
    --features "${KERNEL_FEATURES}" \
    --manifest-path "${ROOT_DIR}/Cargo.toml"

echo "[build] userland"
env RUSTFLAGS="-C relocation-model=static -C link-arg=-T${ROOT_DIR}/examples/user/linker.ld -C link-arg=-no-pie --cfg curve25519_dalek_backend=\"serial\"" \
    cargo build \
    --release \
    --target "${USER_TARGET_NAME}" \
    --target-dir "${USER_BUILD_DIR}" \
    --manifest-path "${ROOT_DIR}/examples/user/Cargo.toml"

USER_BIN="${USER_BUILD_DIR}/${USER_TARGET_NAME}/release/user"
CAPTEST_BIN="${USER_BUILD_DIR}/${USER_TARGET_NAME}/release/captest"

need_file "${USER_BIN}"
need_file "${CAPTEST_BIN}"

echo "[build] plugkit test"
env RUSTFLAGS="-C relocation-model=static -C link-arg=-T${ROOT_DIR}/examples/user/linker.ld -C link-arg=-no-pie --cfg curve25519_dalek_backend=\"serial\"" \
    cargo build \
    --release \
    --target "${USER_TARGET_NAME}" \
    --target-dir "${PLUGKIT_BUILD_DIR}" \
    --manifest-path "${ROOT_DIR}/examples/plugkit/test/Cargo.toml"

PLUGKIT_TEST_BIN="${PLUGKIT_BUILD_DIR}/${USER_TARGET_NAME}/release/entry"
need_file "${PLUGKIT_TEST_BIN}"

echo "[check] user binary used for initfs: ${USER_BIN}"
stat "${USER_BIN}"

echo "[check] ELF header"
readelf -h "${USER_BIN}" | grep -E 'Type:|Entry point address:' || true

echo "[check] selftest marker"
strings "${USER_BIN}" | grep -n 'selftest: enter' || true

SIGNATURE_DB_STAGE="${TARGET_DIR}/execution.allowlist"
echo "[build] bootloader"
cargo build \
    --release \
    --target x86_64-unknown-uefi \
    --target-dir "${BOOT_BUILD_DIR}" \
    --manifest-path "${ROOT_DIR}/examples/boot/Cargo.toml"

KERNEL_BIN="${ROOT_DIR}/target/${KERNEL_TARGET_NAME}/release/kernel"
BOOT_BIN="$(
    find "${BOOT_BUILD_DIR}/x86_64-unknown-uefi/release" \
        -maxdepth 1 \
        -type f \
        \( -name 'boot' -o -name 'boot.efi' \) \
        | head -n 1
)"

need_file "${KERNEL_BIN}"

if [[ -z "${BOOT_BIN}" || ! -f "${BOOT_BIN}" ]]; then
    die "bootloader binary not found"
fi

rm -rf "${ESP_DIR}" "${INITFS_STAGE}" "${ROOTFS_STAGE}"
mkdir -p "${ESP_DIR}/EFI/BOOT" "${INITFS_STAGE}/tmp"

install -m 0644 "${KERNEL_BIN}" "${ESP_DIR}/kernel"
install -m 0644 "${BOOT_BIN}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI"

install -m 0755 "${USER_BIN}" "${INITFS_STAGE}/init"
install -m 0755 "${CAPTEST_BIN}" "${INITFS_STAGE}/tmp/captest.bin"
install -m 0755 "${CAPTEST_BIN}" "${INITFS_STAGE}/tmp/unsigned.bin"
install -m 0755 "${USER_BIN}" "${INITFS_STAGE}/tmp/hello.bin"
mkdir -p "${INITFS_STAGE}/plugkit/test"
install -m 0644 "${ROOT_DIR}/examples/plugkit/test/about.toml" "${INITFS_STAGE}/plugkit/test/about.toml"
install -m 0755 "${PLUGKIT_TEST_BIN}" "${INITFS_STAGE}/plugkit/test/entry.elf"
stage_cext_bundles

echo "[build] signature db"
SIGNATURE_DB_ARGS=(
    --output "${SIGNATURE_DB_STAGE}"
    --entry "/init=${USER_BIN}"
    --entry "/plugkit/test/entry.elf=${PLUGKIT_TEST_BIN}"
    --entry "/tmp/hello.bin=${USER_BIN}"
    --entry "/tmp/captest.bin=${CAPTEST_BIN}"
)
perl "${ROOT_DIR}/scripts/signature_db.pl" "${SIGNATURE_DB_ARGS[@]}"

echo "[build] rootfs"
ROOTFS_SOURCE_DIR="${ROOT_DIR}/examples/fs/rootfs" \
INITFS_STAGE="${INITFS_STAGE}" \
ROOTFS_STAGE="${ROOTFS_STAGE}" \
ROOTFS_IMG="${TARGET_DIR}/rootfs.img" \
ROOTFS_CLEAN_INITFS=0 \
SIGNATURE_DB_SRC="${SIGNATURE_DB_STAGE}" \
bash "${ROOT_DIR}/scripts/rootfs.sh"

echo "[build] initfs"
truncate -s 16M "${TARGET_DIR}/initfs.img"
mke2fs -q -t ext2 -b 1024 -d "${INITFS_STAGE}" -F "${TARGET_DIR}/initfs.img"

install -m 0644 "${TARGET_DIR}/initfs.img" "${ESP_DIR}/initfs.img"
install -m 0644 "${TARGET_DIR}/rootfs.img" "${ESP_DIR}/rootfs.img"

echo "[build] ESP"
rm -f "${ESP_IMG}"
truncate -s 64M "${ESP_IMG}"
mkfs.fat -F 32 -n EFI "${ESP_IMG}"

MTOOLS_SKIP_CHECK=1 mmd -i "${ESP_IMG}" ::/EFI
MTOOLS_SKIP_CHECK=1 mmd -i "${ESP_IMG}" ::/EFI/BOOT

MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/kernel" ::/kernel
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/initfs.img" ::/initfs
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/rootfs.img" ::/rootfs
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI

if [[ ! -f "${OVMF_VARS}" ]]; then
    cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS}"
fi

rm -f "${SERIAL_LOG}"
: > "${SERIAL_LOG}"

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
    -drive "if=none,id=rootfs,format=raw,file=${TARGET_DIR}/rootfs.img"
    -device "virtio-blk-pci,drive=rootfs"
)

if [[ "${DEBUG:-0}" != "0" ]]; then
    QEMU_ARGS+=(-s -S)
fi

echo "[run] qemu"
qemu-system-x86_64 "${QEMU_ARGS[@]}" > >(tee -a "${SERIAL_LOG}") 2>&1 &
QEMU_PID=$!

cleanup() {
    if [[ -n "${QEMU_PID:-}" ]]; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

PASS_FOUND=0
KPTI_ENTRY_CHECK_FOUND=0

for _ in $(seq 1 600); do
    if grep -Fq "USERLAND SELF-TEST FAIL" "${SERIAL_LOG}"; then
        echo "fatal: userland self-test reported FAIL" >&2
        exit 1
    fi
    if grep -Eq "PAGE FAULT|Faulting user context:" "${SERIAL_LOG}"; then
        echo "fatal: userland fault observed during validation" >&2
        exit 1
    fi
    if grep -Fq "USERLAND SELF-TEST PASS" "${SERIAL_LOG}"; then
        PASS_FOUND=1
    fi
    if grep -Fq "SYSCALL entry pre-Rust CR3 check passed" "${SERIAL_LOG}"; then
        KPTI_ENTRY_CHECK_FOUND=1
    fi

    if [[ "${PASS_FOUND}" -eq 1 && "${KPTI_ENTRY_CHECK_FOUND}" -eq 1 ]]; then
        break
    fi

    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        break
    fi

    sleep 0.1
done

if [[ "${PASS_FOUND}" -ne 1 ]]; then
    echo "fatal: userland self-test did not report PASS" >&2
    echo "serial log: ${SERIAL_LOG}" >&2
    exit 1
fi

if [[ "${KPTI_ENTRY_CHECK_FOUND}" -ne 1 ]]; then
    echo "fatal: syscall entry KPTI regression check did not report PASS" >&2
    echo "serial log: ${SERIAL_LOG}" >&2
    exit 1
fi

kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
trap - EXIT

echo "[run] userland self-test passed"

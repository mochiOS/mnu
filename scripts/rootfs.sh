#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-${ROOT_DIR}/target/uefi}"
ROOTFS_SOURCE_DIR="${ROOTFS_SOURCE_DIR:-${ROOT_DIR}/examples/fs/rootfs}"
INITFS_STAGE="${INITFS_STAGE:-${TARGET_DIR}/initfs-root}"
ROOTFS_STAGE="${ROOTFS_STAGE:-${TARGET_DIR}/rootfs-root}"
ROOTFS_IMG="${ROOTFS_IMG:-${TARGET_DIR}/rootfs.img}"
ROOTFS_SIZE="${ROOTFS_SIZE:-16M}"
ROOTFS_BLOCK_SIZE="${ROOTFS_BLOCK_SIZE:-1024}"
ROOTFS_CLEAN_INITFS="${ROOTFS_CLEAN_INITFS:-1}"
SIGNATURE_DB_SRC="${SIGNATURE_DB_SRC:-}"

die() {
    echo "fatal: $*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

need_file() {
    [[ -e "$1" ]] || die "required file not found: $1"
}

need_cmd cp
need_cmd find
need_cmd mke2fs
need_cmd mkdir
need_cmd truncate

need_file "${ROOTFS_SOURCE_DIR}"

mkdir -p "$(dirname "${ROOTFS_IMG}")"
rm -rf "${ROOTFS_STAGE}"
mkdir -p "${ROOTFS_STAGE}"

if [[ "${ROOTFS_CLEAN_INITFS}" != "0" ]]; then
    rm -rf "${INITFS_STAGE}"
fi
mkdir -p "${INITFS_STAGE}"

cp -a "${ROOTFS_SOURCE_DIR}/." "${ROOTFS_STAGE}/"
cp -a "${ROOTFS_SOURCE_DIR}/." "${INITFS_STAGE}/"

if [[ -f "${ROOTFS_SOURCE_DIR}/../testdata" ]]; then
    install -m 0644 "${ROOTFS_SOURCE_DIR}/../testdata" "${ROOTFS_STAGE}/testdata"
    install -m 0644 "${ROOTFS_SOURCE_DIR}/../testdata" "${INITFS_STAGE}/testdata"
fi

if [[ -n "${SIGNATURE_DB_SRC}" ]]; then
    need_file "${SIGNATURE_DB_SRC}"
    install -m 0644 "${SIGNATURE_DB_SRC}" "${ROOTFS_STAGE}/signature.db"
fi

truncate -s "${ROOTFS_SIZE}" "${ROOTFS_IMG}"
mke2fs -q -t ext2 -b "${ROOTFS_BLOCK_SIZE}" -d "${ROOTFS_STAGE}" -F "${ROOTFS_IMG}"

#!/usr/bin/env python3
"""Run CPU, context and AArch64 exception/EL0 diagnostics in QEMU fixtures.

These probes are CPU diagnostics, not a kernel boot or Domain isolation test.
TCG is used for deterministic instruction checks; OS KVM targets are unchanged.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


CORE = Path(__file__).resolve().parents[1]


def executable(name):
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"required executable not found: {name}")
    return str(Path(found).resolve())


def drive(path):
    return str(path).replace(",", ",,")


def run(command, log, timeout, expected=0, marker=None, env=None):
    try:
        result = subprocess.run(
            command, cwd=CORE, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout,
        )
        output = result.stdout
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        log.write_bytes(output)
        raise RuntimeError(f"timed out after {timeout}s; see {log}") from error
    log.write_bytes(output)
    if result.returncode != expected or (marker and marker.encode() not in output):
        raise RuntimeError(
            f"exit {result.returncode}, expected {expected}"
            f"{'; missing ' + marker if marker else ''}; see {log}"
        )


def check(architecture, args, out):
    target = {
        "aarch64": "aarch64-unknown-none",
        "x86_64": "x86_64-unknown-uefi",
    }[architecture]
    binary = out / ("aarch64.elf" if architecture == "aarch64" else "BOOTX64.EFI")
    build = [
        "rustc", f"+{args.toolchain}", "--edition", "2021", "--crate-type", "bin",
        "--target", target, "-C", "panic=abort", "-C", "opt-level=2",
        str(CORE / "scripts/arch-probe.rs"), "-o", str(binary),
    ]
    if architecture == "aarch64":
        build += ["-C", f"link-arg=-T{CORE / 'scripts/arch-probe.ld'}"]
    run(build, out / f"{architecture}-build.log", 60)

    qemu = executable(args.qemu_aarch64 if architecture == "aarch64" else args.qemu_x86_64)
    common = [
        "-accel", "tcg", "-m", "128M", "-smp", "1", "-display", "none",
        "-monitor", "none", "-nic", "none", "-serial", "stdio", "-no-reboot",
    ]
    marker = f"ARCH PRIMITIVES PASS {architecture}"
    env = dict(os.environ, TMPDIR=str(out))
    if architecture == "aarch64":
        command = [
            qemu, "-machine", "virt-8.2,virtualization=on,gic-version=2",
            "-cpu", "cortex-a57", *common, "-kernel", str(binary),
            "-semihosting-config", "enable=on,target=native",
        ]
        run(command, out / "aarch64-run.log", 15, marker=marker, env=env)
    else:
        firmware = args.firmware.resolve()
        code = firmware / "OVMF_CODE_4M.fd"
        variables = firmware / "OVMF_VARS_4M.fd"
        if not code.is_file() or not variables.is_file():
            raise RuntimeError(f"unkeyed OVMF_CODE_4M.fd and OVMF_VARS_4M.fd required in {firmware}")
        with tempfile.TemporaryDirectory(prefix="x86-fixture.", dir=out) as directory:
            fixture = Path(directory)
            boot = fixture / "esp/EFI/BOOT"
            boot.mkdir(parents=True)
            shutil.copyfile(binary, boot / "BOOTX64.EFI")
            shutil.copyfile(variables, fixture / "vars.fd")
            command = [
                qemu, "-machine", "q35", "-cpu", "qemu64", *common,
                "-drive", f"if=pflash,format=raw,readonly=on,file={drive(code)}",
                "-drive", f"if=pflash,format=raw,file={drive(fixture / 'vars.fd')}",
                "-drive", f"format=raw,file=fat:rw:{drive(fixture / 'esp')}",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
            ]
            run(command, out / "x86_64-run.log", 30, expected=33, marker=marker, env=env)
    print(f"{architecture}: PASS ({out / (architecture + '-run.log')})", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["aarch64", "x86_64", "all"], default="all")
    parser.add_argument("--toolchain", default="nightly-2026-05-14")
    parser.add_argument("--out", type=Path, default=CORE / "out/mdp/cpu-primitives")
    parser.add_argument("--qemu-aarch64", default="qemu-system-aarch64")
    parser.add_argument("--qemu-x86-64", dest="qemu_x86_64", default="qemu-system-x86_64")
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF"))
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    try:
        for architecture in ["aarch64", "x86_64"] if args.arch == "all" else [args.arch]:
            check(architecture, args, out)
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"CPU primitive check failed: {error}\n")


if __name__ == "__main__":
    main()

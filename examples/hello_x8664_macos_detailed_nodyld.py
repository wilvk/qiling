#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# A richer companion to hello_x8664_macos_nodyld.py: it runs a more substantial
# dynamically-linked macOS binary WITHOUT a dynamic linker by stubbing a small
# set of libSystem functions in Python.
#
# The target (rootfs/x8664_macos/bin/x8664_detailed) is built from
# examples/src/macos/x8664_detailed.c on a macOS host:
#
#     ./examples/scripts/build_macos_detailed.sh
#
# It exercises printf (several conversions), the heap (malloc/free), string and
# memory routines, snprintf (a fortified __snprintf_chk), getpid, a direct
# write(), and the stack protector (___stack_chk_guard data import).

import os
import struct
import sys

sys.path.append("..")

from qiling import Qiling
from qiling.arch.models import X86_CPU_MODEL
from qiling.const import QL_VERBOSE

# reuse the Mach-O parsing / formatting helpers from the basic example
from hello_x8664_macos_nodyld import (
    discover_stubs,
    discover_data_imports,
    read_cstr,
    c_format,
    ret_with,
)

ROOTFS = r"rootfs/x8664_macos"
TARGET = fr"{ROOTFS}/bin/x8664_detailed"

SENTINEL = 0x1337beef


# ---- a tiny libSystem in Python ----
def stub_printf(ql: Qiling) -> None:
    regs = ql.arch.regs
    s = c_format(ql, read_cstr(ql, regs.rdi).decode("latin1"),
                 [regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9])
    ql.os.stdout.write(s.encode("latin1"))
    ret_with(ql, len(s))


def stub_puts(ql: Qiling) -> None:
    s = read_cstr(ql, ql.arch.regs.rdi)
    ql.os.stdout.write(s + b"\n")
    ret_with(ql, len(s) + 1)


def stub_malloc(ql: Qiling) -> None:
    ret_with(ql, ql.os.heap.alloc(max(ql.arch.regs.rdi, 1)))


def stub_free(ql: Qiling) -> None:
    try:
        ql.os.heap.free(ql.arch.regs.rdi)
    except Exception:
        pass
    ret_with(ql, 0)


def stub_memset(ql: Qiling) -> None:
    regs = ql.arch.regs
    ql.mem.write(regs.rdi, bytes([regs.rsi & 0xFF]) * regs.rdx)
    ret_with(ql, regs.rdi)


def stub_memcpy(ql: Qiling) -> None:
    regs = ql.arch.regs
    ql.mem.write(regs.rdi, ql.mem.read(regs.rsi, regs.rdx))
    ret_with(ql, regs.rdi)


def stub_strlen(ql: Qiling) -> None:
    ret_with(ql, len(read_cstr(ql, ql.arch.regs.rdi)))


def stub_getpid(ql: Qiling) -> None:
    ret_with(ql, 9999)


def stub_write(ql: Qiling) -> None:
    regs = ql.arch.regs
    data = bytes(ql.mem.read(regs.rsi, regs.rdx))
    stream = ql.os.stderr if regs.rdi == 2 else ql.os.stdout
    stream.write(data)
    ret_with(ql, regs.rdx)


def stub_strcpy_chk(ql: Qiling) -> None:           # __strcpy_chk(dst, src, dstlen)
    regs = ql.arch.regs
    ql.mem.write(regs.rdi, read_cstr(ql, regs.rsi) + b"\x00")
    ret_with(ql, regs.rdi)


def stub_snprintf_chk(ql: Qiling) -> None:         # __snprintf_chk(str, maxlen, flag, slen, fmt, ...)
    regs = ql.arch.regs
    fmt = read_cstr(ql, regs.r8).decode("latin1")
    # varargs after the format: r9, then stack slots above the return address
    stack_args = [struct.unpack("<Q", ql.mem.read(regs.rsp + 8 + 8 * i, 8))[0] for i in range(6)]
    s = c_format(ql, fmt, [regs.r9] + stack_args)
    body = s.encode("latin1")[:max(regs.rsi - 1, 0)]
    ql.mem.write(regs.rdi, body + b"\x00")
    ret_with(ql, len(s))


def stub_stack_chk_fail(ql: Qiling) -> None:
    ql.os.stderr.write(b"*** stack smashing detected (__stack_chk_fail) ***\n")
    ql.emu_stop()


STUBS = {
    "_printf": stub_printf,
    "_puts": stub_puts,
    "_malloc": stub_malloc,
    "_free": stub_free,
    "_memset": stub_memset,
    "_memcpy": stub_memcpy,
    "_strlen": stub_strlen,
    "_getpid": stub_getpid,
    "_write": stub_write,
    "___strcpy_chk": stub_strcpy_chk,
    "___snprintf_chk": stub_snprintf_chk,
    "___stack_chk_fail": stub_stack_chk_fail,
}


def my_sandbox():
    if not os.path.exists(TARGET):
        sys.exit(f"{TARGET} not found - build it first: ./examples/scripts/build_macos_detailed.sh")

    ql = Qiling([TARGET], ROOTFS, cputype=X86_CPU_MODEL.INTEL_HASWELL, verbose=QL_VERBOSE.OFF)
    assert not ql.loader.using_dyld, "expected no-dyld mode (remove dyld from the rootfs)"

    slide = ql.loader.slide

    # hook each imported function stub
    for addr, name in discover_stubs(TARGET).items():
        impl = STUBS.get(name)

        if impl is None:
            def make_logger(symbol):
                def _log(ql: Qiling):
                    ql.log.warning(f"unhandled libc call: {symbol}")
                    ret_with(ql, 0)
                return _log

            impl = make_logger(name)

        ql.hook_address(impl, addr + slide)

    # bind non-lazy / GOT data imports (e.g. ___stack_chk_guard) with backing cells
    for slot, name in discover_data_imports(TARGET).items():
        if name == "dyld_stub_binder":
            continue

        cell = ql.os.heap.alloc(8)
        value = 0xA5A5A5A5A5A5A500 if name == "___stack_chk_guard" else 0
        ql.mem.write(cell, struct.pack("<Q", value))
        ql.mem.write(slot + slide, struct.pack("<Q", cell))

    # set up main(argc, argv, envp, apple) and a sentinel return, then jump in
    kstack = ql.loader.stack_sp
    (argc,) = struct.unpack("<Q", ql.mem.read(kstack, 8))

    regs = ql.arch.regs
    regs.rdi = argc
    regs.rsi = kstack + 8
    regs.rdx = kstack + 8 + (argc + 1) * 8
    regs.rcx = 0

    frame = (kstack - 0x800) & ~0xF
    ql.mem.write(frame - 8, struct.pack("<Q", SENTINEL))
    regs.rsp = frame - 8

    ql.emu_start(ql.loader.entry_point, SENTINEL)
    print(f"[main returned {ql.arch.regs.rax & 0xff}]")


if __name__ == "__main__":
    my_sandbox()

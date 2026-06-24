#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# An advanced demonstration of running a dynamically-linked macOS binary WITHOUT
# a dynamic linker (see hello_x8664_macos_nodyld.py for the basics).
#
# The target (rootfs/x8664_macos/bin/x8664_advanced, built from
# examples/src/macos/x8664_advanced.c via examples/scripts/build_macos_advanced.sh)
# leverages a broad slice of libSystem. Notably it exercises:
#   * fprintf to stdout/stderr        -> the __stdoutp / __stderrp data imports
#   * the stack protector             -> the ___stack_chk_guard data import
#   * qsort with a comparator         -> libc calling BACK INTO guest code
#
# The qsort callback is the interesting case: a stubbed libc routine must invoke
# a function pointer that lives in the emulated program. We can't nest emulation
# from inside a hook, so qsort is driven as a small state machine: each
# comparison redirects execution into the guest comparator with a trampoline as
# its return address; the trampoline hook collects the result and issues the next
# comparison (or returns to qsort's caller).

import os
import struct
import sys

sys.path.append("..")

from qiling import Qiling
from qiling.arch.models import X86_CPU_MODEL
from qiling.const import QL_VERBOSE

from hello_x8664_macos_nodyld import (
    discover_stubs,
    discover_data_imports,
    read_cstr,
    c_format,
    ret_with,
)

ROOTFS = r"rootfs/x8664_macos"
TARGET = fr"{ROOTFS}/bin/x8664_advanced"

SENTINEL = 0x1337beef
TRAMP = 0x90000000          # qsort comparator return trampoline
COMP_STACK_TOP = 0x91010000  # scratch stack for comparator calls
STDOUT_SENT = 0x7FFF0001     # sentinel FILE* values bound into __stdoutp/__stderrp
STDERR_SENT = 0x7FFF0002


def _sb(v: int, bits: int = 32) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def _write(ql: Qiling, stream_id: int, data: bytes) -> None:
    (ql.os.stderr if stream_id == STDERR_SENT else ql.os.stdout).write(data)


# ---------------- a small libSystem in Python ----------------
def s_printf(ql):
    r = ql.arch.regs
    s = c_format(ql, read_cstr(ql, r.rdi).decode("latin1"), [r.rsi, r.rdx, r.rcx, r.r8, r.r9])
    _write(ql, STDOUT_SENT, s.encode("latin1")); ret_with(ql, len(s))


def s_fprintf(ql):
    r = ql.arch.regs
    s = c_format(ql, read_cstr(ql, r.rsi).decode("latin1"), [r.rdx, r.rcx, r.r8, r.r9])
    _write(ql, r.rdi, s.encode("latin1")); ret_with(ql, len(s))


def s_fputs(ql):
    r = ql.arch.regs
    _write(ql, r.rsi, read_cstr(ql, r.rdi)); ret_with(ql, 1)


def s_putchar(ql):
    r = ql.arch.regs
    _write(ql, STDOUT_SENT, bytes([r.rdi & 0xFF])); ret_with(ql, r.rdi & 0xFF)


def s_malloc(ql):
    ret_with(ql, ql.os.heap.alloc(max(ql.arch.regs.rdi, 1)))


def s_calloc(ql):
    r = ql.arch.regs
    n = max(r.rdi * r.rsi, 1)
    p = ql.os.heap.alloc(n); ql.mem.write(p, b"\x00" * n); ret_with(ql, p)


def s_realloc(ql):
    r = ql.arch.regs
    p = ql.os.heap.alloc(max(r.rsi, 1))
    if r.rdi:
        try:
            p_old = bytes(ql.mem.read(r.rdi, min(r.rsi, ql.os.heap.size(r.rdi))))
            ql.mem.write(p, p_old)
        except Exception:
            pass
    ret_with(ql, p)


def s_free(ql):
    try:
        ql.os.heap.free(ql.arch.regs.rdi)
    except Exception:
        pass
    ret_with(ql, 0)


def s_memcpy_chk(ql):   # (dst, src, len, dstlen)
    r = ql.arch.regs
    ql.mem.write(r.rdi, bytes(ql.mem.read(r.rsi, r.rdx))); ret_with(ql, r.rdi)


def s_strcpy_chk(ql):   # (dst, src, dstlen)
    r = ql.arch.regs
    ql.mem.write(r.rdi, read_cstr(ql, r.rsi) + b"\x00"); ret_with(ql, r.rdi)


def s_strcat_chk(ql):   # (dst, src, dstlen)
    r = ql.arch.regs
    base = read_cstr(ql, r.rdi)
    ql.mem.write(r.rdi + len(base), read_cstr(ql, r.rsi) + b"\x00"); ret_with(ql, r.rdi)


def s_strncpy_chk(ql):  # (dst, src, len, dstlen)
    r = ql.arch.regs
    src = read_cstr(ql, r.rsi)[:r.rdx]
    src += b"\x00" * (r.rdx - len(src))
    ql.mem.write(r.rdi, src); ret_with(ql, r.rdi)


def s_strlen(ql):
    ret_with(ql, len(read_cstr(ql, ql.arch.regs.rdi)))


def s_strchr(ql):
    r = ql.arch.regs; s = read_cstr(ql, r.rdi); i = s.find(bytes([r.rsi & 0xFF]))
    ret_with(ql, r.rdi + i if i >= 0 else 0)


def s_strrchr(ql):
    r = ql.arch.regs; s = read_cstr(ql, r.rdi); i = s.rfind(bytes([r.rsi & 0xFF]))
    ret_with(ql, r.rdi + i if i >= 0 else 0)


def s_strstr(ql):
    r = ql.arch.regs; h = read_cstr(ql, r.rdi); i = h.find(read_cstr(ql, r.rsi))
    ret_with(ql, r.rdi + i if i >= 0 else 0)


def s_strcmp(ql):
    r = ql.arch.regs; a = read_cstr(ql, r.rdi); b = read_cstr(ql, r.rsi)
    ret_with(ql, (a > b) - (a < b))


def s_strncmp(ql):
    r = ql.arch.regs; n = r.rdx
    a = read_cstr(ql, r.rdi)[:n]; b = read_cstr(ql, r.rsi)[:n]
    ret_with(ql, (a > b) - (a < b))


def s_memcmp(ql):
    r = ql.arch.regs
    a = bytes(ql.mem.read(r.rdi, r.rdx)); b = bytes(ql.mem.read(r.rsi, r.rdx))
    ret_with(ql, (a > b) - (a < b))


def s_toupper(ql):
    ret_with(ql, ord(chr(ql.arch.regs.rdi & 0xFF).upper()))


def s_tolower(ql):
    ret_with(ql, ord(chr(ql.arch.regs.rdi & 0xFF).lower()))


def s_isdigit(ql):
    ret_with(ql, 1 if chr(ql.arch.regs.rdi & 0xFF).isdigit() else 0)


def s_strtol(ql):
    r = ql.arch.regs
    s = read_cstr(ql, r.rdi).decode("latin1"); base = r.rdx or 10
    i = 0
    while i < len(s) and s[i] in " \t":
        i += 1
    j = i
    if j < len(s) and s[j] in "+-":
        j += 1
    while j < len(s) and s[j].isdigit():
        j += 1
    try:
        val = int(s[i:j], base)
    except ValueError:
        val = 0
    if r.rsi:
        ql.mem.write(r.rsi, struct.pack("<Q", r.rdi + j))
    ret_with(ql, val)


def s_atoi(ql):
    s = read_cstr(ql, ql.arch.regs.rdi).decode("latin1").strip()
    m = ""
    for k, ch in enumerate(s):
        if ch.isdigit() or (k == 0 and ch in "+-"):
            m += ch
        else:
            break
    ret_with(ql, int(m) if m not in ("", "+", "-") else 0)


def s_abs(ql):
    ret_with(ql, abs(_sb(ql.arch.regs.rdi)))


def s_snprintf_chk(ql):  # (str, maxlen, flag, os, fmt, ...)
    r = ql.arch.regs
    fmt = read_cstr(ql, r.r8).decode("latin1")
    stack = [struct.unpack("<Q", ql.mem.read(r.rsp + 8 + 8 * i, 8))[0] for i in range(6)]
    s = c_format(ql, fmt, [r.r9] + stack)
    ql.mem.write(r.rdi, s.encode("latin1")[:max(r.rsi - 1, 0)] + b"\x00"); ret_with(ql, len(s))


def s_sprintf_chk(ql):   # (str, flag, os, fmt, ...)
    r = ql.arch.regs
    fmt = read_cstr(ql, r.rcx).decode("latin1")
    s = c_format(ql, fmt, [r.r8, r.r9])
    ql.mem.write(r.rdi, s.encode("latin1") + b"\x00"); ret_with(ql, len(s))


def s_getpid(ql):
    ret_with(ql, 9999)


def s_getuid(ql):
    ret_with(ql, 501)


def s_time(ql):
    r = ql.arch.regs; t = 0x60000000
    if r.rdi:
        ql.mem.write(r.rdi, struct.pack("<Q", t))
    ret_with(ql, t)


def s_getenv(ql):
    name = read_cstr(ql, ql.arch.regs.rdi).decode("latin1")
    if name == "PATH":
        p = ql.os.heap.alloc(16); ql.mem.write(p, b"/usr/bin\x00"); ret_with(ql, p)
    else:
        ret_with(ql, 0)


def s_stack_chk_fail(ql):
    ql.os.stderr.write(b"*** stack smashing detected (__stack_chk_fail) ***\n")
    ql.emu_stop()


# ---------------- qsort driven via a comparator trampoline ----------------
_qs = {}


def _issue_compare(ql, ia: int, ib: int) -> None:
    r = ql.arch.regs
    r.rdi = _qs["base"] + ia * _qs["size"]
    r.rsi = _qs["base"] + ib * _qs["size"]
    sp = (COMP_STACK_TOP & ~0xF) - 8
    ql.mem.write(sp, struct.pack("<Q", TRAMP))
    r.rsp = sp
    r.rip = _qs["compar"]
    _qs["pending"] = (ia, ib)


def _finish_qsort(ql) -> None:
    r = ql.arch.regs
    r.rax = 0
    r.rsp = _qs["ret_rsp"] + 8
    r.rip = _qs["caller_ret"]


def s_qsort(ql):        # qsort(base, nmemb, size, compar) -- bubble sort via callback
    r = ql.arch.regs
    _qs.update(base=r.rdi, n=r.rsi, size=r.rdx, compar=r.rcx, i=0, j=0, ret_rsp=r.rsp,
               caller_ret=struct.unpack("<Q", ql.mem.read(r.rsp, 8))[0])
    if _qs["n"] < 2:
        _finish_qsort(ql)
    else:
        _issue_compare(ql, 0, 1)


def s_qsort_trampoline(ql):
    base, size, n = _qs["base"], _qs["size"], _qs["n"]
    ia, ib = _qs["pending"]

    if _sb(ql.arch.regs.rax) > 0:   # comparator said element[ia] should come after element[ib]
        a = bytes(ql.mem.read(base + ia * size, size))
        b = bytes(ql.mem.read(base + ib * size, size))
        ql.mem.write(base + ia * size, b)
        ql.mem.write(base + ib * size, a)

    _qs["j"] += 1
    if _qs["j"] < n - 1 - _qs["i"]:
        _issue_compare(ql, _qs["j"], _qs["j"] + 1)
    else:
        _qs["i"] += 1
        _qs["j"] = 0
        if _qs["i"] < n - 1:
            _issue_compare(ql, 0, 1)
        else:
            _finish_qsort(ql)


STUBS = {
    "_printf": s_printf, "_fprintf": s_fprintf, "_fputs": s_fputs, "_putchar": s_putchar,
    "_malloc": s_malloc, "_calloc": s_calloc, "_realloc": s_realloc, "_free": s_free,
    "___memcpy_chk": s_memcpy_chk, "___memmove_chk": s_memcpy_chk,
    "___strcpy_chk": s_strcpy_chk, "___strcat_chk": s_strcat_chk, "___strncpy_chk": s_strncpy_chk,
    "_strlen": s_strlen, "_strchr": s_strchr, "_strrchr": s_strrchr, "_strstr": s_strstr,
    "_strcmp": s_strcmp, "_strncmp": s_strncmp, "_memcmp": s_memcmp,
    "_toupper": s_toupper, "_tolower": s_tolower, "_isdigit": s_isdigit,
    "_strtol": s_strtol, "_atoi": s_atoi, "_abs": s_abs,
    "___snprintf_chk": s_snprintf_chk, "___sprintf_chk": s_sprintf_chk,
    "_getpid": s_getpid, "_getuid": s_getuid, "_time": s_time, "_getenv": s_getenv,
    "_qsort": s_qsort, "___stack_chk_fail": s_stack_chk_fail,
}


def my_sandbox():
    if not os.path.exists(TARGET):
        sys.exit(f"{TARGET} not found - build it first: ./examples/scripts/build_macos_advanced.sh")

    ql = Qiling([TARGET], ROOTFS, cputype=X86_CPU_MODEL.INTEL_HASWELL, verbose=QL_VERBOSE.OFF)
    assert not ql.loader.using_dyld, "expected no-dyld mode"

    slide = ql.loader.slide

    # scratch memory for the qsort comparator trampoline
    ql.mem.map(0x90000000, 0x2000)
    ql.mem.write(TRAMP, b"\xc3")          # a placeholder 'ret'
    ql.mem.map(0x91000000, 0x11000)       # comparator scratch stack
    ql.hook_address(s_qsort_trampoline, TRAMP)

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

    # bind data imports: stdout/stderr FILE* sentinels and a stack canary cell
    data_values = {
        "___stdoutp": STDOUT_SENT,
        "___stderrp": STDERR_SENT,
        "___stack_chk_guard": 0xA5A5A5A5A5A5A500,
    }

    for slot, name in discover_data_imports(TARGET).items():
        if name == "dyld_stub_binder":
            continue

        cell = ql.os.heap.alloc(8)
        ql.mem.write(cell, struct.pack("<Q", data_values.get(name, 0)))
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

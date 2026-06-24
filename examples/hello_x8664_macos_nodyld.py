#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Run a dynamically-linked macOS (Mach-O) binary WITHOUT a dynamic linker.
#
# The stock x8664_macos rootfs does not ship Apple's proprietary /usr/lib/dyld,
# and a modern host dyld cannot be emulated by Qiling's classic-dyld-era loader.
# Instead of loading dyld, this example relies on Qiling's no-dyld fallback (the
# loader runs the binary directly when dyld is absent) and satisfies the binary's
# libSystem imports with small Python stubs.
#
# It works by:
#   1. discovering the __stubs -> imported-symbol mapping from the Mach-O
#      indirect symbol table,
#   2. hooking each stub with a Python implementation (here: printf / puts),
#   3. setting up main(argc, argv, envp, apple) per the SysV ABI and jumping
#      straight to the LC_MAIN entry point.

import struct
import sys

sys.path.append("..")

from qiling import Qiling
from qiling.arch.models import X86_CPU_MODEL
from qiling.const import QL_VERBOSE

ROOTFS = r"rootfs/x8664_macos"
TARGET = fr"{ROOTFS}/bin/x8664_hello"

# sentinel return address: emulation stops when main() returns to it
SENTINEL = 0x1337beef


def discover_stubs(path: str) -> dict:
    """Map each __stubs entry address to the imported symbol it represents,
    using the Mach-O indirect symbol table (no dyld required)."""

    data = open(path, "rb").read()

    (magic,) = struct.unpack_from("<I", data, 0)
    assert magic == 0xFEEDFACF, "expected a thin 64-bit Mach-O"

    (ncmds,) = struct.unpack_from("<I", data, 16)
    off = 32

    symoff = stroff = 0
    indirectsymoff = 0
    stub_sects = []  # (addr, size, reserved1 index, reserved2 entsize)

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)

        if cmd == 0x19:  # LC_SEGMENT_64
            (nsects,) = struct.unpack_from("<I", data, off + 64)
            so = off + 72

            for _s in range(nsects):
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                (flags,) = struct.unpack_from("<I", data, so + 64)
                reserved1, reserved2 = struct.unpack_from("<II", data, so + 68)

                if (flags & 0xFF) == 0x08:  # S_SYMBOL_STUBS
                    stub_sects.append((addr, size, reserved1, reserved2))

                so += 80

        elif cmd == 0x02:  # LC_SYMTAB
            symoff, _nsyms, stroff, _strsize = struct.unpack_from("<IIII", data, off + 8)

        elif cmd == 0x0B:  # LC_DYSYMTAB
            indirectsymoff, _nindirect = struct.unpack_from("<II", data, off + 56)

        off += cmdsize

    def sym_name(symidx: int) -> str:
        (n_strx,) = struct.unpack_from("<I", data, symoff + symidx * 16)
        end = data.index(b"\x00", stroff + n_strx)
        return data[stroff + n_strx:end].decode()

    mapping = {}

    for addr, size, reserved1, entsize in stub_sects:
        for i in range(size // entsize):
            (ind,) = struct.unpack_from("<I", data, indirectsymoff + (reserved1 + i) * 4)
            mapping[addr + i * entsize] = sym_name(ind)

    return mapping


def read_cstr(ql: Qiling, ptr: int, maxlen: int = 8192) -> bytes:
    out = bytearray()

    while len(out) < maxlen:
        ch = ql.mem.read(ptr + len(out), 1)

        if ch == b"\x00":
            break

        out += ch

    return bytes(out)


def c_format(ql: Qiling, fmt: str, args) -> str:
    """A minimal printf-style formatter (enough for typical demos)."""

    out, ai, i = [], 0, 0

    while i < len(fmt):
        c = fmt[i]

        if c == "%" and i + 1 < len(fmt):
            j = i + 1

            while j < len(fmt) and fmt[j] in "-+ #0123456789.lhzL":
                j += 1

            spec = fmt[j] if j < len(fmt) else "%"

            if spec == "%":
                out.append("%")
            else:
                a = args[ai] if ai < len(args) else 0

                if spec in "di":
                    out.append(str(a - (1 << 64) if a >> 63 else a)); ai += 1
                elif spec == "u":
                    out.append(str(a)); ai += 1
                elif spec in "xX":
                    out.append(format(a, spec)); ai += 1
                elif spec == "p":
                    out.append(hex(a)); ai += 1
                elif spec == "c":
                    out.append(chr(a & 0xFF)); ai += 1
                elif spec == "s":
                    out.append(read_cstr(ql, a).decode("latin1")); ai += 1
                else:
                    out.append("%" + spec)

            i = j + 1
        else:
            out.append(c)
            i += 1

    return "".join(out)


def ret_with(ql: Qiling, value: int) -> None:
    """Set the return value and emulate `ret`, skipping the unbound stub jmp."""

    ql.arch.regs.rax = value & 0xFFFFFFFFFFFFFFFF

    (retaddr,) = struct.unpack("<Q", ql.mem.read(ql.arch.regs.rsp, 8))
    ql.arch.regs.rsp += 8
    ql.arch.regs.rip = retaddr


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


STUBS = {
    "_printf": stub_printf,
    "_puts": stub_puts,
}


def my_sandbox():
    ql = Qiling([TARGET], ROOTFS, cputype=X86_CPU_MODEL.INTEL_HASWELL, verbose=QL_VERBOSE.OFF)

    # the loader falls back to no-dyld mode because the rootfs has no /usr/lib/dyld
    assert not ql.loader.using_dyld, "expected no-dyld mode (remove dyld from the rootfs)"

    slide = ql.loader.slide

    for addr, name in discover_stubs(TARGET).items():
        impl = STUBS.get(name)

        if impl is None:
            # unhandled import: log it and return 0 so emulation can proceed
            def make_logger(symbol):
                def _log(ql: Qiling):
                    ql.log.warning(f"unhandled libc call: {symbol}")
                    ret_with(ql, 0)
                return _log

            impl = make_logger(name)

        ql.hook_address(impl, addr + slide)

    # build SysV ABI state for main(argc, argv, envp, apple), bypassing libdyld glue
    kstack = ql.loader.stack_sp
    (argc,) = struct.unpack("<Q", ql.mem.read(kstack, 8))

    regs = ql.arch.regs
    regs.rdi = argc
    regs.rsi = kstack + 8
    regs.rdx = kstack + 8 + (argc + 1) * 8
    regs.rcx = 0

    # a fresh, 16-byte-aligned call frame with the sentinel as the return address
    frame = (kstack - 0x800) & ~0xF
    ql.mem.write(frame - 8, struct.pack("<Q", SENTINEL))
    regs.rsp = frame - 8

    ql.emu_start(ql.loader.entry_point, SENTINEL)


if __name__ == "__main__":
    my_sandbox()

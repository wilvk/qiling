#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_RDI,
    UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_EFLAGS
)

from qiling.os.posix.syscall.abi import QlSyscallABI


class QlIntel32(QlSyscallABI):
    """System call ABI for Intel-based 32-bit systems.
    """

    _idreg = UC_X86_REG_EAX
    _argregs = (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP)
    _retreg = UC_X86_REG_EAX


class QlIntel64(QlSyscallABI):
    """System call ABI for Intel-based 64-bit systems.
    """

    _idreg = UC_X86_REG_RAX
    _argregs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9)
    _retreg = UC_X86_REG_RAX


class QlIntel64Macos(QlIntel64):
    """System call ABI for macOS on Intel 64-bit.

    Darwin distinguishes syscall classes by the high bits of the syscall number
    and signals UNIX-class (0x2000000) errors via the carry flag, returning a
    *positive* errno in rax - unlike the Linux convention of a negative return.
    Mach traps (0x1000000) and machdep traps (0x3000000) keep kern_return_t
    semantics and are returned verbatim.
    """

    _CF = 1 << 0  # carry flag in EFLAGS

    def get_id(self) -> int:
        # cache the id so set_return_value can tell which class this call belongs to
        self._last_id = super().get_id()
        return self._last_id

    def set_return_value(self, value: int) -> None:
        is_unix = 0x2000000 <= getattr(self, '_last_id', 0) < 0x3000000

        if not is_unix:
            super().set_return_value(value)
            return

        eflags = self.arch.regs.read(UC_X86_REG_EFLAGS)

        # Qiling posix handlers encode failures as a small negative errno
        if isinstance(value, int) and -0x1000 < value < 0:
            self.arch.regs.write(self._retreg, -value)
            self.arch.regs.write(UC_X86_REG_EFLAGS, eflags | self._CF)
        else:
            self.arch.regs.write(self._retreg, value)
            self.arch.regs.write(UC_X86_REG_EFLAGS, eflags & ~self._CF)

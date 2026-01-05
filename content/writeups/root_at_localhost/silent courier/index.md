---
title: 'Silent Courier'
date: 2024-12-09T00:00:07+05:30
draft: false
---

## The statement

A mysterious file is being secretly transferred between servers. Your task is to intercept the transfer and uncover the hidden secret. Can you track it down before it's too late?

## Solution

File is analyzed using [apacket](https://apackets.com/).

![apacket is goated](/posts/root@localhost_writeup_assets/silent_courier/apacket.png)

The zip file is encrypted.
> [!Terminal]+ unzip protected.zip
> Archive:  protected.zip
> [protected.zip] secret.zip password: %

Crack it with johntheripper
> [!Terminal]+ zip2john protected.zip > zip.hash
> ver 2.0 Scanning for EOD... FOUND Extended local header
> protected.zip/secret.zip PKZIP Encr: cmplen=137, decmplen=178, crc=13905395

> [!Terminal]+ john  --wordlist=/usr/share/dict/rockyou.txt  zip.hash
> [archlinux:61650] shmem: mmap: an error occurred while determining whether or not /tmp/ompi.archlinux.1000/jf.0/4292542464/shared_mem_cuda_pool.archlinux could be created.
> [archlinux:61650] create_and_attach: unable to create shared memory BTL coordinating structure :: size 134217728
> Using default input encoding: UTF-8
> Loaded 1 password hash (PKZIP [32/64])
> Will run 12 OpenMP threads
> Press 'q' or Ctrl-C to abort, almost any other key for status
> supersonic       (protected.zip/secret.zip)
> 1g 0:00:00:00 DONE (2024-12-09 00:49) 50.00g/s 1228Kp/s 1228Kc/s 1228KC/s 123456..271087
> Use the "--show" option to display all of the cracked passwords reliably
> Session completed

### Flag: `root@localhost{Liam_24_P%40ssw0rd!2024}**`

---
title: 'Secret Stash'
date: 2024-12-09T04:11:29+05:30
draft: true
tags:
    - ctf-writeups
---

JohnTheRipper+rockyou.txt is like dhoni+raina combo :pray:.

<!--more-->

## The statement

In a charming old bookstore, an artist’s illustration graces the cover of a vintage volume. The artwork seems like a beautiful enigma, with intricate details and hidden symbols. Among the various elements, one particular design element holds a clue that leads to a hidden archive within the book. The true prize, a coveted flag, rests safely inside a concealed digital treasure. To uncover the secret, examine the image closely and uncover the secret passage to the zip file within.

## Solution

Find unusual passwords from the `steg2_pass.txt`
> [!Terminal]+ strings -13 steg2_pass.txt
> H@rdP@ssw0rd!2024
> UnlockTheImage!

Try manual bruteforce
> [!Terminal]+ steghide extract -sf steg2.jpg -p H@rdP@ssw0rd\!2024
> steghide: could not extract any data with that passphrase!

> [!Terminal]+ steghide extract -sf steg2.jpg -p UnlockTheImage\!
> wrote extracted data to "secret.zip".

Zip file is encrypted
> [!Terminal]+ unzip secret.zip
> Archive:  secret.zip
> [secret.zip] flag.txt password: %

Use good ol' john
> [!Terminal]+ zip2john secret.zip > zip.hash
> ver 1.0 efh 5455 efh 7875 secret.zip/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=49, decmplen=37, crc=FA4E5053

Try given wordlist.
> [!Terminal]+ john  --wordlist=./steg2_pass.txt  zip.hash
> [archlinux:13105] shmem: mmap: an error occurred while determining whether or not /tmp/ompi.archlinux.1000/jf.0/1121648640/shared_mem_cuda_pool.archlinux could be created.
> [archlinux:13105] create_and_attach: unable to create shared memory BTL coordinating structure :: size 134217728
> Using default input encoding: UTF-8
> Loaded 1 password hash (PKZIP [32/64])
> Will run 12 OpenMP threads
> Press 'q' or Ctrl-C to abort, almost any other key for status
> 0g 0:00:00:00 DONE (2024-12-09 04:21) 0g/s 5100p/s 5100c/s 5100C/s 5Fsc"5o'%{`G..]zt+%+.FtY3W
> Session completed

Bring in rockyou.txt + john
> [!Terminal]+ john  --wordlist=/usr/share/dict/rockyou.txt  zip.hash
> [archlinux:13209] shmem: mmap: an error occurred while determining whether or not /tmp/ompi.archlinux.1000/jf.0/2240086016/shared_mem_cuda_pool.archlinux could be created.
> [archlinux:13209] create_and_attach: unable to create shared memory BTL coordinating structure :: size 134217728
> Using default input encoding: UTF-8
> Loaded 1 password hash (PKZIP [32/64])
> Will run 12 OpenMP threads
> Press 'q' or Ctrl-C to abort, almost any other key for status
> cookie1          (secret.zip/flag.txt)
> 1g 0:00:00:00 DONE (2024-12-09 04:22) 100.0g/s 2457Kp/s 2457Kc/s 2457KC/s 123456..271087
> Use the "--show" option to display all of the cracked passwords reliably
> Session completed

> [!Terminal]+ unzip secret.zip
> Archive:  secret.zip
> [secret.zip] flag.txt password:
>    skipping: flag.txt                incorrect password

> [!Terminal]+ cat flag.txt
> root@localhost{SecureByDesign!2024}

### Flag: `root@localhost{SecureByDesign!2024}`

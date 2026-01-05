---
title: 'Play With Qr'
date: 2024-12-09T02:59:24+05:30
draft: false
---

You don't need A GUI FOR SORTING FILES BY SIZE.

<!--more-->

## The statement
Find the correct qr code

## The solution

Upon unzipping the attached archive, there are a lot of qr codes with the same file size.
> [!Terminal]+ ls -lah
> total 4.0M
> drwxrwxr-x 2 sivaplays sivaplays  36K Dec  9 03:01 .
> drwxr-xr-x 3 sivaplays sivaplays 4.0K Dec  7 21:01 ..
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_100.png
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_101.png
> ...
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_997.png
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_998.png
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_999.png
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_99.png
> -rw-rw-r-- 1 sivaplays sivaplays  535 Oct  9 19:49 fake_qr_9.png

One file has a different size, so it has to be the flag
> [!Terminal]+ ls -lh | rg -v 535
> total 4.0M
> -rw-rw-r-- 1 sivaplays sivaplays 528 Oct  9 19:59 fake_qr_669.png

#### Flag: `root@localhost{7h3_q6_!s_fun}`

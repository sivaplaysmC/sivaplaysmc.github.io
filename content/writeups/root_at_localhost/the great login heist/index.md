---
title: 'The Great Login Heist'
date: 2024-12-08T23:48:26+05:30
draft: false
---

## The statement

In a daring attempt at digital mischief, a crafty threat actor tried to break into Cybertown Tech Solutions' secure web interface. Their sneaky login attempts were caught red-handed in a PCAP file, thanks to our vigilant network monitoring.

flag format :root@localhost{username_password}

## Solution

The pcapng file has the following string, which contains the username and password. ez win

![`strings` is enough](/posts/root@localhost_writeup_assets/silent_courier/ss0.png)

**Flag: `root@localhost{Liam_24_P%40ssw0rd!2024}** `

## Quirks

I thought the password (P%40ssw0rd!2024) was meant to be Base64URLdecoded, but the organizers thought otherwise 😅.

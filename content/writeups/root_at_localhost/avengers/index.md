---
title: "Avengers"
date: 2024-12-09T12:30:08+05:30
draft: true
---

Just because you're a fan of Avengers doesn't mean you're good at CTFs.

Pretty niche and weird windows challenge.

<!--more-->

## Statement

My friend John is an "environmental" activist and a humanitarian. He hated the ideology of Thanos from the Avengers: Infinity War. He sucks at programming. He used too many variables while writing any program. One day, John gave me a memory dump and asked me to find out what he was doing while he took the dump. Can you figure it out for me?

## Solution

The file only had raw data, and since it was a memory dump, i search for the related [hacktricks article](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis), and found about a tool called volatility (bcoz `file` command showed zero metadata, and all other memory dumps seem to show at least some details.)

### Final: ``

---
title: 'Hidden Truth'
date: 2024-12-09T03:14:23+05:30
draft: false
---

## The statement

A hidden message lies concealed within a jumble of characters and numbers. Can you crack the code and reveal the secret? The mystery is waiting for you to uncover it.

## Solution

Strings on the file gives a base64 string.
> [!Terminal]+ strings -n 65 challenge.png
> <x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 12.76'>
> <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
>      <Attrib:ExtId>03825ccf-d796-4baa-8dda-96a2acd20326</Attrib:ExtId>
>     <rdf:li xml:lang='x-default'>cm9vdEBsb2NhbGhvc3R7QzBuZ3JAdCRfWTB1X0YwdW5kX1RoM19NeXN0M3J5X04wd30=</rdf:li>
> cm9vdEBsb2NhbGhvc3R7QzBuZ3JAdCRfWTB1X0YwdW5kX1RoM19NeXN0M3J5X04wd30=

Decode it to get flag
> [!Terminal]+ clippaste | base64 -d
> root@localhost{C0ngr@t$_Y0u_F0und_Th3_Myst3ry_N0w}%

#### Flag: `root@localhost{C0ngr@t$_Y0u_F0und_Th3_Myst3ry_N0w}%`

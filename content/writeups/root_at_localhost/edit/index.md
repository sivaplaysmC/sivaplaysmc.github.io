---
title: Edit
date: 2024-12-09T12:21:06+05:30
draft: true
---

PNG Format is cool and Vim + xxd is the only hex editor you'll ever need.


<!--more-->

## Solution

The file can't be opened as a PNG, suggesting that the header has been tampered.

> [!Terminal]+ feh chall.png
> feh WARNING: chall.png - Does not look like an image (magic bytes missing)
> feh: No loadable images specified.
> See 'feh --help' or 'man feh' for detailed usage information

The header is obviously tampered. Edit it vim and xxd.

> [!Terminal]+ xxd chall.png | head -n 5
> 00000000: 9050 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
> 00000010: 0000 035c 0000 035c 0806 0000 004b e5ae  ...\...\.....K..
> 00000020: c400 0000 2063 4852 4d00 007a 2600 0080  .... cHRM..z&...
> 00000030: 8400 00fa 0000 0080 e800 0075 3000 00ea  ...........u0...
> 00000040: 6000 003a 9800 0017 709c ba51 3c00 0000  `..:....p..Q<...

After editing:

> [!Terminal]+ xxd chall.png | head -n 5
> 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
> 00000010: 0000 035c 0000 035c 0806 0000 004b e5ae  ...\...\.....K..
> 00000020: c400 0000 2063 4852 4d00 007a 2600 0080  .... cHRM..z&...
> 00000030: 8400 00fa 0000 0080 e800 0075 3000 00ea  ...........u0...
> 00000040: 6000 003a 9800 0017 709c ba51 3c00 0000  `..:....p..Q<...

![Flag](/posts/root@localhost_writeup_assets/edit.png)

### Flag: `r00t@localhost{D4t4_C3nt3r_0p3r4t0r!}`

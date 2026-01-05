---
title: 'Ez Web'
date: 2024-12-09T04:41:52+05:30
draft: false
---

## The statement

duh.

## Solution
Inspect the html and find js file.

![Ctrl-Shift-I](/posts/root@localhost_writeup_assets/ezweb-1.png)

Find this encoded string in js file.

```js
const encodedFlag: 'cm9vdEBsb2NhbGhvc3R7VGhlX3dlYl9jaGFsbF9pc19lYXN5fQ==';
```

Decode it
> [!Terminal]+ base64 -d <<< cm9vdEBsb2NhbGhvc3R7VGhlX3dlYl9jaGFsbF9pc19lYXN5fQ==
> root@localhost{The_web_chall_is_easy}

### Flag: `root@localhost{The_web_chall_is_easy}`

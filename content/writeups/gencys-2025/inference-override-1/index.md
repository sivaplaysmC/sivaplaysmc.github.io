---
date: '2025-08-25T13:02:33+05:30'
title: 'Inference Override 1'
tags:
- web
- query-parameter-injection
- php
---

Log in to website using info leak in an internal route, and use query-parameter-injection to pollute locals.

BTW Always look at robots.txt :thumbs:.

<!--more-->

This challenge requires escalating privileges to `gold` tier. There doesn't seem to be any way to do this.


## Recon

`index.php` redirects to `login.php`, which requires valid user credentials. So start standard web enumeration, and discover `/api/creds.php` route in `robots.txt`.

## Solve

### Initial Foothold

The `/api/creds.php` gives login credentials which work in `/login.php`

```json
{
    "username": "johndoe",
    "password": "Summer2025!"
}
```

### PHP Variable injection

There is a simple php website, with a only little useful information - only the `/deals.php` mentions anything about the tier.

Since this is website is written in PHP, I tried `variable injection` to override the value of the `tier` variable.

`http://shop.gencyscorp.in/deals.php?tier=gold`

Never expected this to work, but it did.

#### Why it worked

My hypothesis is that the php file does something like

```
explode($_GET);
```

Which pollutes the locals. The result is a variable called `tier` with the value `gold` is created, which overrides the flow of the application.

## Flag

`USTCtf{REDACTED}`

Note: Flag has been redacted.

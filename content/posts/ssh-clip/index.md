---
date: '2025-09-22T12:11:26+05:30'
title: 'Ssh Clip'
---


Clipboard with SSH cause graphical web interfaces are just too overkill for copying text.


<!--more-->

---

## Try it NOW

To **upload** content:

```sh
echo hi | ssh trash@ansr.mooo.com -p 8080 u first_message
```

To **download** saved content:

```sh
ssh trash@ansr.mooo.com -p 8080 d first_message
```

> Here, `trash` acts as a "clipboard slot" name — you can use any name you like.
first_message is the name of the file you'd like to store.


---

## How it works

### SSH as a protocol

SSH, [is actually a protocol](https://datatracker.ietf.org/doc/html/rfc4251). The `ssh` and `sshd` commands are just clients and servers that (unironically) communicate via the `ssh` protocol.

This means that we can provide a spec-compliant custom implementation for the server, and any `ssh` client should be able to communicate with the server just fine.

### Written in go

The core of the implementation is a `sshd` like server program written in [`go`](https://go.dev/). I chose `go` here because of two main reasons:

1. I know it pretty good.
2. It has amazing ssh support built right into the standard library (Batteries included).

I also used [github.com/gliderlabs/ssh](https://github.com/gliderlabs/ssh), mainly because it provides an interface to write ssh handlers just like http hanlders.

Sample SSH handler in go:
```go
ssh.Handle(
    func(s ssh.Session) {
        op := s.Command()[0]

        switch op {
            /// ...
        }
    },
)

```

Sample HTTP handler in go:
```go
http.HandleFunc("/",
    func(w http.ResponseWriter, r *http.Request) {
        op := r.FormValue("op")

        switch op {
            /// ...
        }
    },
)
```

### Operations

For now, `ssh-clip` supports upload and download of content. Content can be text, binary or even a directory of files (given that you `tar` or `zip` it before and after).

## Why not SCP?

`scp` is a tool built specifically for transfer of files over an `ssh` connection. Even though it is standard, for my use case of carelessly copying around text, it has a few downsides:

1. It requires creating a restricted user account and handling file permissions when deploying it.
2. It requires some sort of identity verification - either through passwords or ssh keys.

## Security Concerns

PLEASE DON'T STORE SENSITIVE CREDENTIALS / SECRET KEYS / PASSWORDS with `ssh-clip` while using the ***public instance***. Everything is stored in plain text in the server's file system.

If you want a private storage, you can always self-host your own copy of `ssh-clip` on your own server and not share it's port to others - it's as simple as running it yourself. Keep in mind that no verification of usernames is done, so if people have your instance's IP and PORT, they can access and store files in it.

## Source

Get the source code here:
1. [Github](https://github.com/sivaplaysmC/ssh-clip)

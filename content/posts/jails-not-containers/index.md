---
date: '2026-03-25T16:27:20+05:30'
title: "Jails, Not Containers: A CTFer's PWN Environment with Nix and Bwrap"
---

My story of migrating from `docker` containers to a more hacky `bwrap` + `nix` based jail for isolated, low-friction, reproducible security research environments.

<!--more-->

## Preface

A few months ago, I was using [pwntainer](https://github.com/sivaplaysmc/pwntainer) -
a docker based reproducible isolated environment for CTFs and PWN for most of the CTF challenges (pwn category),
and it had quite a few rough edges:

### Dangerous capabilities and privileges

1.  I had to run the container with `--privileged` for getting `gdb-with-qemu` and other services to work inside the container.

2.  `/sys` and `/dev` was exposed inside the container - nothing was stopping a rogue binary from doing
    ```bash
    sudo cat /dev/urandom > /dev/nvme0n1
    ```
### Cumbersome package management

1.  Adding pacakages was cumbersome

    I was using different package managers for different utilities - I installed

    1.  `yazi` with source
    2.  `fzf` with github
    3.  `ROPGadget` (and hell a lot of other python packages) with `uv`
    4.  `onegadget` and `seccomp-tools` with `gem`

    Everytime I wanted a new package, it was becoming more unwieldy to install - I had to use a specific command for installing that package,
    and installing it in one container didnt make it available in another container - I had to download the packages again.

1.  Adding new tools to the image was more of a chore.

    If I wanted to add a new python package, say, `angr` to the list of python deps, I had to edit the
    `uv add` line in my dockerfile - which meant anything below it would have to be rebuilt from scratch.

    The situation is worse for adding packages installed through `apt`, that would result in the ENTIRE image being rebuilt.

## The partial solution - `nix` and `bubblewrap`

All of the shortcomings with `pwntainer` can be mitigated by using `nix` with `bwrap` -
but it ended up highlighting features of docker that I took for granted. (Check [Challenge](#the-challenge))

### Package management with `nix`

The `nix` package manager, is by-design, used to create reproducible systems.
It allowed specifying all necessary pacakges in a single file, and it would cache package installs.

As of 2026, It has around 120,000 packages, and it also includes language specific packages.

That means no longer using three different package managers - nix alone is enough
for installing and using packages. A simple example:

```nix
pythonWithPkgs = pkgs.python3.withPackages (
    ps: with ps; [
      pip
      pwntools
      ropgadget
      ipython
      ipdb
    ]
  )
)
rubyWithGems = pkgs.ruby.withPackages (
    ps: with ps; [
        one_gadget
        seccomp-tools
    ]
);
env = pkgs.buildEnv {
    name = "pwn-env";
    paths = [
        pythonWithPkgs
        rubyWithGems
        pkgs.yazi
        pkgs.neovim
    ]
}
```

Adding new packages becomes less of a chore, since `nix` caches package downloads and stores them inside `/nix/store`.

That means adding `angr` does not trigger rebuild of entire system - it just fetches angr and places it in `PYTHONPATH`.

### Isolation with bwrap

Bubblewrap (`argv[0] = bwrap`) is tiny, no-setuid binary that can be used to create "jails".
It provides isolation by creating new kernel namespaces for things like processes, mounts, hostname, etc.

It provides complete filesystem isolation by mounting a directory as root,
and allows mounting shared directories using overlayfs.

For `pwnix`, I used the following bwrap setup:

1. Mount a static rootfs as an overlayfs (`lowerdir` = `immutable rootfs`, `upperdir` = `mountpoint inside jail`, `workdir` = `empty dir in host`)

```
--overlay-src "$PWNIX_ROOTFS/"
--overlay "$PWNIX_UPPER_DIR" "$PWNIX_WORK_DIR" /
```

2. Create completely separated `/dev`, `/proc`, `/tmp`

```
--dev /dev --proc /proc --tmpfs /tmp \
```

3. Mount cwd (R/W) into jail

```
--bind "$PWD" /root/work \
```

4. Unshare all namespaces (except net) and setup netowrking

```
--ro-bind /etc/resolv.conf /etc/resolv.conf \
--unshare-all
--share-net
```


## The challenge

In my old `pwntainer` workflow, each running container **was like a VM** - I could freely detach from it, and attach to it as neeeded, and it just worked.

But `bwrap` and `nix` by themselves, dont have any such features - which meant I had to come up with something by myself for getting VM like functionality.

## Enter [`pwnixctl`](https://github.com/sivaplaysmc/pwnix.git)

To mitigate above challenges, I created a simple python script, which stored a bunch of metadata about jail during startup. It included the following metadata:

1. jail pid and namespaces
2. path of `zsh` executable inside nix store

Using the above metadata, I was able to create, start, stop, resume and dispose off jails at will with `nix`, `bwrap`, and `nsenter`.

1.  On create, I initialized flake.nix for that specific jail.
2.  On start
    1. I started the bwrap jail with `sleep infinity` and wrote metadata (jail pid, zsh path)
    2.  Wrote nix environment variables (PATH, TERMINFO_DB, etc.) to `/etc/zprofile` so it can be accessed by future login shells.
        (Because `nsenter` has no way to inherit env vars from the jail process)

3.  On attach, I used `nsenter`, jail pid, and zsh path to get a shell inside the jail.
4.  On stop, I simply killed the process group of the jail process.

## Closing thoughts

Sure, one can say this as a over-engineered hafl-baked reimplementation of a few features of docker - but I now understand why those features exist in the first place.
Namespaces, overlayfs, environment inheritance, process groups - docker abstracts all of this away, hiding it behind a pleasant `docker run`.

Building pwnix forced me to reason about each layer explicitly, and now my threat model is something I actually understand rather than something I just hope docker handles correctly.

Besides CTF PWN, I used `pwnix` to setup more elevated jails fine-tuned for certain situations. For example, I setup a `pwnix` jail for reverse-engineering firmware of Kai-OS devices, by providing
access ONLY to `/dev/ttyUSB0` (used for qualcomm EDL communication) and hiding everything else from an untrusted `EDL.py` script that would usually require elevated privileges for working properly.




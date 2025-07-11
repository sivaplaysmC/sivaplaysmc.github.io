---
title: 'Pixel Secrets'
date: 2024-12-09T03:39:07+05:30
draft: false
---

## The statement

Decode the hidden message embedded in this image. Use steganographic techniques to uncover the flag that lies beneath the pixels!

## Solution

Should be pretty self explanatory. Classic steganography bruteforce.

```terminal
$ docker run --rm -it -v '$(pwd):/steg' rickdejager/stegseek  steg1.jpg  password.txt
Unable to find image 'rickdejager/stegseek:latest' locally
latest: Pulling from rickdejager/stegseek
a70d879fa598: Pull complete
c4394a92d1f8: Pull complete
10e6159c56c0: Pull complete
2a9284816e0c: Pull complete
da918f5114c3: Pull complete
172662ab993b: Pull complete
Digest: sha256:a3c6a82d5b7dd94dc49098c5080a70da8103b7ed3b3718423b3a70d4b43c9a8a
Status: Downloaded newer image for rickdejager/stegseek:latest
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "ej,;m=;$IL}@"
[i] Original filename: "flag.txt".
[i] Extracting to "steg1.jpg.out".
```

```terminal
$ cat steg1.jpg.out
root@localhost{H1dd3n_M3ss4g3_F0und}
```

### Flag: `root@localhost{H1dd3n_M3ss4g3_F0und}`

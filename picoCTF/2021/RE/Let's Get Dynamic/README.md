# Let's Get Dynamic [150 Points] - 231 Solves

```
Can you tell what this file is reading? chall.S
```

We are given a `chall.s`, which is is x86 assembly code.

I first tried to annotate and attempt to solve the challenge without relying on dynamic analysis. But after sometime, it proved to be quite tedious as I needed some way to "clean" the strings and hexadecimal values which were being moved into the registers.

Hence, I decided to compile `chall.s` using the following commands:

```bash
ld -s -o file file.out #Note you have to use ld instead of nasm as this is AT&T syntax, not intel
gcc -m64 file.out -o file #Since it uses C libraries, you have to use gcc to link it
```

Throwing it into IDA, we get:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int i; // [rsp+1Ch] [rbp-114h]
  char s2[64]; // [rsp+20h] [rbp-110h] BYREF
  char s[64]; // [rsp+60h] [rbp-D0h] BYREF
  char v7[8]; // [rsp+A0h] [rbp-90h] BYREF
  __int64 v8; // [rsp+A8h] [rbp-88h]
  __int64 v9; // [rsp+B0h] [rbp-80h]
  __int64 v10; // [rsp+B8h] [rbp-78h]
  __int64 v11; // [rsp+C0h] [rbp-70h]
  char v12[16]; // [rsp+C8h] [rbp-68h] BYREF
  __int64 v13[6]; // [rsp+E0h] [rbp-50h]
  __int16 v14; // [rsp+110h] [rbp-20h]
  unsigned __int64 v15; // [rsp+118h] [rbp-18h]

  v15 = __readfsqword(0x28u);
  *(_QWORD *)v7 = 0xBC85B660F86F4BLL;
  v8 = 0x1681DB12439C495CLL;
  v9 = 0x42D1A76C289682B0LL;
  v10 = 0xF36D20D4AD376ECCLL;
  v11 = 0xEEF9E715D337B2A2LL;
  strcpy(v12, "\xF8\xF0\xAB\x77\x9C\xBD\xFD\x11o");
  v13[0] = 0x6FEFC7E21F8A1428LL;
  v13[1] = 0x55FFF4606FEB2A23LL;
  v13[2] = 0x19A7901244A3EE87LL;
  v13[3] = 0x8D535EAE906117F6LL;
  v13[4] = 0x85A0A444D075F5CELL;
  v13[5] = 0x48F6E1952EA1FDF1LL;
  v14 = 0x31;
  fgets(s, 49, _bss_start);
  for ( i = 0; i < strlen(v7); ++i )
    s2[i] = *((_BYTE *)v13 + i) ^ v7[i] ^ i ^ 19;
  if ( !memcmp(s, s2, 49uLL) )
  {
    puts("No, that's not right.");
    result = 1;
  }
  else
  {
    puts("Correct! You entered the flag.");
    result = 0;
  }
  return result;
}
```

It seems like our input is first obtained from `fgets` and saved into `s`

We can note that the length of the flag is `49` characters based off `memcmp(s, s2, 49uLL)` and `fgets(s, 49, _bss_start)`.

A char array `s2` is then populated through some xoring operations based off `v13` and `v7`(Note: `v7` is an array which includes `v8`, `v9`, `v10` and `v11`) before being **compared with our input**. Hence we can deduce that `s2` contains the **decoded flag**. Let's head over to `gdb` and just get it's value!

But... after stopping at the compare instruction..

```assembly
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdca0 --> 0x7fffffff000a --> 0x0
RBX: 0x7
RCX: 0x7fffffffdc60 --> 0x4654436f636970 ('picoCTF')
RDX: 0x31 ('1')
RSI: 0x7fffffffdc60 --> 0x4654436f636970 ('picoCTF')
RDI: 0x7fffffffdca0 --> 0x7fffffff000a --> 0x0
RBP: 0x7fffffffdd70 --> 0x555555554990 (<__libc_csu_init>:      push   r15)
RSP: 0x7fffffffdc40 --> 0x7fffffffde58 --> 0x7fffffffe081 
RIP: 0x55555555493e (<main+372>:        call   0x555555554690 <memcmp@plt>)
R8 : 0x7ffff7dcf8c0 --> 0x0
R9 : 0x7ffff7fdf4c0 (0x00007ffff7fdf4c0)
R10: 0x555555756010 --> 0x0
R11: 0x346
R12: 0x5555555546c0 (<_start>:  xor    ebp,ebp)
R13: 0x7fffffffde50 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555554933 <main+361>:   mov    edx,0x31
   0x555555554938 <main+366>:   mov    rsi,rcx
   0x55555555493b <main+369>:   mov    rdi,rax
=> 0x55555555493e <main+372>:   call   0x555555554690 <memcmp@plt>
   0x555555554943 <main+377>:   test   eax,eax
   0x555555554945 <main+379>:   je     0x55555555495a <main+400>
   0x555555554947 <main+381>:   lea    rdi,[rip+0xca]        # 0x555555554a18
   0x55555555494e <main+388>:   call   0x555555554660 <puts@plt>
```

We realise that `rsi` only contains the string `picoCTF`, which is clearly the beginning of the flag, but nothing else.

At this point I got stuck and sought help from a teammate. Apparently, what happened is that there is a null character `\x00` inside `v7`. Hence, `v7` looks something like `0xBC85B660F86F4B00` in little-endian, which means that `for ( i = 0; i < strlen(v7); ++i ) s2[i] = *((_BYTE *)v13 + i) ^ v7[i] ^ i ^ 19;` **runs only 6 times since `strlen` returns `6` only** (producing `picoCTF` only)

If we convert it to big-endian, `v7` will look something like `0x00BC85B660F86F4B`, and we can write a python script to decrypt it: *(Alternatively, you could always patch the binary to fix the `strlen`)*

```python
v14 = [""] * 7

v14[0] = "6FEFC7E21F8A1428"
v14[1] = "55FFF4606FEB2A23"
v14[2] = "19A7901244A3EE87"
v14[3] = "8D535EAE906117F6"
v14[4] = "85A0A444D075F5CE"
v14[5] = "48F6E1952EA1FDF1"
v14[6] = "31"

v12HexArray = []
for x in v14:
    truncated = x.zfill(8)
    tbytes = bytearray.fromhex(truncated)
    tbytes.reverse()
    truncated = tbytes.hex()
    for y in range(0, len(truncated), 2):
        v12HexArray.append(truncated[y:y+2])

v7 = [""] * 7 
v7[0] = "00BC85B660F86F4B" #There is a null byte at the front (in MSB), which causes everything to be deviated by 1
                           #(This would be at the back in LSB, which causes the strlen() function to return an incorrect length and only return "picoCTF")
v7[1] = "1681DB12439C495C"
v7[2] = "42D1A76C289682B0"
v7[3] = "F36D20D4AD376ECC"
v7[4] = "EEF9E715D337B2A2"
v7[5] = "11FDBD9C77ABF0F8"
v7[6] = "6F"

v7HexArray = []

for x in v7:
    truncated = x.zfill(8)
    tbytes = bytearray.fromhex(truncated)
    tbytes.reverse()  
    truncated = tbytes.hex()
    for y in range(0, len(truncated), 2):
        v7HexArray.append(truncated[y:y+2])


flag = []
for x in range(0, len(v7HexArray), 1):
    flag.append(chr(int(v12HexArray[x],16) ^ int(v7HexArray[x], 16) ^ x ^ 19))
print(''.join(flag))
```

And we get the flag:

```
picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_273a6b6e}
```



## Learning Points

- Compiling assembly into binaries
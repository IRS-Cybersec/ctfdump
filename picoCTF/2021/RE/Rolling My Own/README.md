# Rolling My Own [300 Points]

```
I don't trust password checkers made by other people, so I wrote my own. It doesn't even need to store the password! If you can crack it I'll give you a flag. nc mercury.picoctf.net 35226
```

## Hints

1. It's based on [this paper](https://link.springer.com/article/10.1007%2Fs11416-006-0011-3)
2. Here's the start of the password: `D1v1`

------

We are given the ELF64 `remote` file.

Running it asks us to input a password. When we try to input any password, it seems to give `Segmentation fault`.

```
./remote
Password: jdhhdqued
Segmentation fault
```

Let's first analyse it in IDA and look at the `main` function:

## Main Function

```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int lengthOfdest; // eax
  __int64 v4; // rdx
  int i; // [rsp+8h] [rbp-F8h]
  int j; // [rsp+8h] [rbp-F8h]
  int k; // [rsp+Ch] [rbp-F4h]
  void (__fastcall *v9)(__int64 (__fastcall *)()); // [rsp+10h] [rbp-F0h]
  _BYTE *ptr; // [rsp+18h] [rbp-E8h]
  int v11[4]; // [rsp+20h] [rbp-E0h]
  __int64 v12[2]; // [rsp+30h] [rbp-D0h]
  char v13[48]; // [rsp+40h] [rbp-C0h] BYREF
  char s[64]; // [rsp+70h] [rbp-90h] BYREF
  char dest[72]; // [rsp+B0h] [rbp-50h] BYREF
  unsigned __int64 v16; // [rsp+F8h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  strcpy(v13, "GpLaMjEWpVOjnnmkRGiledp6Mvcezxls");
  v11[0] = 8;
  v11[1] = 2;
  v11[2] = 7;
  v11[3] = 1;
  memset(s, 0, sizeof(s));
  memset(dest, 0, 0x40uLL);
  printf("Password: ");
  fgets(s, 64, stdin);
  s[strlen(s) - 1] = 0;                         // sets null char
  for ( i = 0; i <= 3; ++i )
  {
    strncat(dest, &s[4 * i], 4uLL);             // In each iteration (4 times):
                                                // - Append 4 chars of input
                                                // - Append 8 chars of string
                                                // Total length = 16 + 32 = 48
    strncat(dest, &v13[8 * i], 8uLL);
  }
  ptr = malloc(64uLL);
  lengthOfdest = strlen(dest);
  sub_E3E((__int64)ptr, (__int64)dest, lengthOfdest);
  for ( j = 0; j <= 3; ++j )                    // jumbles up MD5 output shellcode
                                                // 
                                                // [1st MD5]: x x x x x x x x C C C C x x x x
                                                // [2nd MD5]: x x C C C C x x x x x x x x x x
  {
    for ( k = 0; k <= 3; ++k )
      *((_BYTE *)v12 + 4 * k + j) = ptr[16 * k + j + v11[k]];// ptr saved to v12
  }
  v9 = (void (__fastcall *)(__int64 (__fastcall *)()))mmap(0LL, 0x10uLL, 7, 34, -1, 0LL);
  v4 = v12[1];
  *(_QWORD *)v9 = v12[0];                       // pointer saved to v9
  *((_QWORD *)v9 + 1) = v4;
  v9((__int64 (__fastcall *)())flag_func);      // v9 is called as a function
  free(ptr);
  return 0LL;
}
```

*As you can see, I have added some comments and renamed some variables to the code. The following is a summary of what it does:*

- We first see that our input is saved into a variable `s` 

  ```c
  printf("Password: ");
  fgets(s, 64, stdin);
  ```

- A `for` loop then appends **4 characters** of our input and **8 characters** of the string `strcpy(v13, "GpLaMjEWpVOjnnmkRGiledp6Mvcezxls");` in each iteration to the variable `dest`.

  - We can deduce that the length of the input should be **16 bytes** since it runs 4 times * 4 = 16 chars. The total length of dest would hence be 32+16=48 chars

  - ```c
      for ( i = 0; i <= 3; ++i )
      {
        strncat(dest, &s[4 * i], 4uLL);             // In each iteration (4 times):
                                                    // - Append 4 chars of input
                                                    // - Append 8 chars of string
                                                    // Total length = 16 + 32 = 48
        strncat(dest, &v13[8 * i], 8uLL);
      }
    ```

- Memory space is then allocated and saved to `ptr` in ` ptr = malloc(64uLL);` 

- A function is called with `ptr`, `dest` and `lengthOfdest` which is the length of dest.

  ```c
  lengthOfdest = strlen(dest);
  sub_E3E((__int64)ptr, (__int64)dest, lengthOfdest);
  ```



## sub_E3E (Hashing Function)

```c
unsigned __int64 __fastcall sub_E3E(__int64 mallocPTR, __int64 dest, int lengthOfdest)
{
  int lengthQuotient; // eax
  int i; // [rsp+20h] [rbp-90h]
  int j; // [rsp+24h] [rbp-8Ch]
  int lenOfBytesToHash; // [rsp+28h] [rbp-88h]
  int lengthQuotient2; // [rsp+2Ch] [rbp-84h]
  char someMD5Struc[96]; // [rsp+30h] [rbp-80h] BYREF
  char MD5Hash[24]; // [rsp+90h] [rbp-20h] BYREF
  unsigned __int64 v13; // [rsp+A8h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  if ( lengthOfdest % 12 )
    lengthQuotient = lengthOfdest / 12 + 1;
  else
    lengthQuotient = lengthOfdest / 12;         // if factors of 12, come here
  lengthQuotient2 = lengthQuotient;
  for ( i = 0; i < lengthQuotient2; ++i )
  {
    lenOfBytesToHash = 12;
    if ( i == lengthQuotient2 - 1 && lengthOfdest % 12 )// if last iteration && input is not perfect factors of 12
                                                // get the length of the last chunk
      lenOfBytesToHash = lengthQuotient2 % 12;
    MD5_Init(someMD5Struc);
    MD5_Update(someMD5Struc, dest, lenOfBytesToHash);// Note: dest is a pointer
                                                // MD5_Update(Hash, data, len) - Hashes len of data into hash
    dest += lenOfBytesToHash;
    MD5_Final(MD5Hash, someMD5Struc);
    for ( j = 0; j <= 15; ++j )
      *(_BYTE *)(mallocPTR + (j + 16 * i) % 64) = MD5Hash[j];// appends all 3 MD5 hashes into PTR
  }
  return __readfsqword(0x28u) ^ v13;
}
```

In sub_E3E, we see references to `MD5` hashing. 

- The first part simply calculates how many blocks of 12 there are (the last block need not be a full block of 12)

  ```c
    if ( lengthOfdest % 12 )
      lengthQuotient = lengthOfdest / 12 + 1;
    else
      lengthQuotient = lengthOfdest / 12;         // if factors of 12, come here
    lengthQuotient2 = lengthQuotient;
  ```

- The `for` loop hashes **blocks of 12 characters (or less) of `dest`** into MD5 hashes. The MD5 hashes are appended to the variable `ptr` that was passed into the function.

- ```C
    for ( i = 0; i < lengthQuotient2; ++i )
    {
      lenOfBytesToHash = 12;
      if ( i == lengthQuotient2 - 1 && lengthOfdest % 12 )// if last iteration && input is not perfect factors of 12
                                                  // get the length of the last chunk
        lenOfBytesToHash = lengthQuotient2 % 12;
      MD5_Init(someMD5Struc);
      MD5_Update(someMD5Struc, dest, lenOfBytesToHash);// Note: dest is a pointer
                                                  // MD5_Update(Hash, data, len) - Hashes len of data into hash
      dest += lenOfBytesToHash;
      MD5_Final(MD5Hash, someMD5Struc);
      for ( j = 0; j <= 15; ++j )
        *(_BYTE *)(mallocPTR + (j + 16 * i) % 64) = MD5Hash[j];// appends all 3 MD5 hashes into PTR
    }
  ```

  

Let's look back at the `main` function

- The `for` loop immediately after `sub_E3E` **saves certain parts of the MD5 hash** into a `v12` pointer (which is later called as "shellcode")

  ```C
   for ( j = 0; j <= 3; ++j )                    // takes specific positions of the MD5 output shellcode marked by a "C"
                                                  // 
                                                  // [1st MD5]: x x x x x x x x C C C C x x x x
                                                  // [2nd MD5]: x x C C C C x x x x x x x x x x
    {
      for ( k = 0; k <= 3; ++k )
        *((_BYTE *)v12 + 4 * k + j) = ptr[16 * k + j + v11[k]]; // ptr saved to v12
    }
  ```

- ```c
  v4 = v12[1];
  *(_QWORD *)v9 = v12[0];                       // pointer saved to v9
  *((_QWORD *)v9 + 1) = v4;
  v9((__int64 (__fastcall *)())flag_func);      // v9 is called as a function
  ```

  - `v12` pointer is then saved to `v9`, which is called along with the address of `flag_func` as the parameter.

Let's take a look at `flag_func`

## flag_func

```c
unsigned __int64 __fastcall sub_102B(__int64 a1)
{
  FILE *stream; // [rsp+18h] [rbp-98h]
  char s[136]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v4; // [rsp+A8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( a1 == 0x7B3DC26F1LL )                    // we need to pass a parameter with 0x7B3DC26F1
  {
    stream = fopen("flag", "r");
    if ( !stream )
    {
      puts("Flag file not found. Contact an admin.");
      exit(1);
    }
    fgets(s, 128, stream);
    puts(s);
  }
  else
  {
    puts("Hmmmmmm... not quite");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

- It seems like when `flag_func` is called with the parameter with value `0x7B3DC26F1`, it will open the flag file (on the remote server) and send the flag to us.

------

## What we have to do

In summary, we have to: Write a **password** that gets converted to an **MD5 hash** with the **specific bytes which form a shellcode that calls `flag_func`** with the parameter  `0x7B3DC26F1`

Let's take a closer look at the part where our shellcode is called **in assembly**:

```assembly
mov     rax, [rbp+var_F0] ; a pointer to the bytes from the MD5 hash (i.e our shellcode) is moved into rax
lea     rdi, flag_func  ; sub_102B address passed into register rdi
call    rax             ; rax (i.e our shellcode) is then called
                        
```

Hence we can write the following shellcode:

```assembly
mov rsi, rdi ; save address of flag_func into rsi
mov rdi, 0x7B3DC26F1 ; move required value into rdi (pass parameters via registers)
call rsi
```

We can then assemble it using `pwntools` `asm()`

```python
>>> shellcode = """
... mov rsi, rdi
... mov rdi, 0x7B3DC26F1
... call rsi
... """
>>> asm(shellcode, arch="amd64").hex()
'4889fe48bff126dcb307000000ffd6'
```

I then wrote a [bruteforce script](RMOBruteforce.py) to **look for the password** that **generates the MD5 hashes** with the bytes of the shellcode we need.

And we get the following password:

```
Found smth!
D1v1
Found smth!
d3An
Found smth!
dC0n
Found smth!
\rpB
```

Entering it into the remote server gets us the flag:

```
nc mercury.picoctf.net 35226
Password: D1v1d3AndC0n\rpB
picoCTF{r011ing_y0ur_0wn_crypt0_15_h4rd!_dae85416}
```

------

## Learning Points

- Anti-decompilation technique using hash functions (as mentioned in the research paper)
- Writing "shellcode"

**<u>Side-note:</u>** Some writeups state the password as `D1v1d3AndC0nqu3r`, which is probably the intended password. However, we only need the specific bytes at specific positions of the MD5 hash to be the ones we wanted for the program to work. Hence `\rpB` works as well.
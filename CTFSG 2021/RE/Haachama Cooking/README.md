# Haachama Cooking [989 Points] - 5 Solves

```
Welcome to Haachama cooking! Today's I'm going to make my very own blend of AES! A little sprinkle of concurrency... Or was it parallism? Whatever, either one will work, this should still taste better than the tarantula ramen I had last time anyway.

(Note: The youtube link is only a *cultured* bgm recommendation by the challenge creator and has nothing to do with the solution.)

Author: violenttestpen
```



## Initial Analysis

We are given the ELF-32 `haachama-cooking`

Running it, we can `Enter Your Flag Here: ` prompt, entering random stuff says `Invalid Flag Length`.

Let's take a look at the source code!

I first tried to look at strings, but unfortunately, I was unable to find the strings such as `Enter Your Flag Here:` or `Invalid Flag Length`, so I decided to take a look at the main function:

```c
void __cdecl main_main()
{
  _DWORD *v0; // eax
  int i; // ecx
  int v2; // esi
  unsigned int v3; // ebp
  int v4; // edx
  unsigned int v5; // ecx
  int v6; // [esp+0h] [ebp-ACh]
  int v7; // [esp+4h] [ebp-A8h]
  int v8; // [esp+4h] [ebp-A8h]
  int v9; // [esp+4h] [ebp-A8h]
  int v10; // [esp+8h] [ebp-A4h]
  int v11; // [esp+8h] [ebp-A4h]
  int v12; // [esp+Ch] [ebp-A0h]
  int v13; // [esp+Ch] [ebp-A0h]
  int v14; // [esp+Ch] [ebp-A0h]
  int v15; // [esp+Ch] [ebp-A0h]
  int v16; // [esp+Ch] [ebp-A0h]
  int v17; // [esp+Ch] [ebp-A0h]
  char v18; // [esp+Ch] [ebp-A0h]
  char v19; // [esp+Ch] [ebp-A0h]
  int v20; // [esp+10h] [ebp-9Ch]
  int v21; // [esp+10h] [ebp-9Ch]
  int v22; // [esp+10h] [ebp-9Ch]
  int v23; // [esp+10h] [ebp-9Ch]
  int v24; // [esp+10h] [ebp-9Ch]
  int v25; // [esp+14h] [ebp-98h]
  int v26; // [esp+14h] [ebp-98h]
  __int16 v27; // [esp+14h] [ebp-98h]
  int v28; // [esp+18h] [ebp-94h]
  int v29; // [esp+28h] [ebp-84h]
  int v30; // [esp+2Ch] [ebp-80h]
  int v31; // [esp+38h] [ebp-74h]
  unsigned int v32; // [esp+40h] [ebp-6Ch]
  int v33; // [esp+44h] [ebp-68h]
  int v34; // [esp+48h] [ebp-64h]
  int v35; // [esp+4Ch] [ebp-60h]
  _DWORD *v36; // [esp+50h] [ebp-5Ch]
  int v37[2]; // [esp+54h] [ebp-58h] BYREF
  int v38[2]; // [esp+5Ch] [ebp-50h] BYREF
  int v39[2]; // [esp+64h] [ebp-48h] BYREF
  int v40[2]; // [esp+6Ch] [ebp-40h] BYREF
  int v41[2]; // [esp+74h] [ebp-38h] BYREF
  void *v42; // [esp+7Ch] [ebp-30h] BYREF
  int v43[3]; // [esp+80h] [ebp-2Ch] BYREF
  int v44[4]; // [esp+8Ch] [ebp-20h] BYREF
  int v45[4]; // [esp+9Ch] [ebp-10h] BYREF

  if ( (unsigned int)v43 <= *(_DWORD *)(*(_DWORD *)(__readgsdword(0) - 4) + 8) )
    runtime_morestack_noctxt();
  v41[0] = (int)&unk_80E7360;
  v41[1] = (int)&off_8115788;
  fmt_Fprint(&go_itab__os_File_io_Writer, os_Stdout, v41, 1, 1);
  runtime_newobject(&unk_80E7360, v7);
  v36 = (_DWORD *)v8;
  v40[0] = (int)&unk_80E3020;
  v40[1] = v8;
  fmt_Fscanln(&go_itab__os_File_io_Reader, os_Stdin, v40, 1, 1);
  v0 = v36;
  if ( v36[1] != 64 )
  {
    v39[0] = (int)&unk_80E7360;
    v39[1] = (int)&off_8115790;
    fmt_Fprintln(&go_itab__os_File_io_Writer, os_Stdout, v39, 1, 1);
    os_Exit(1);
  }
  v45[0] = 0;
  v45[1] = 0;
  v45[2] = 0;
  v45[3] = 0;
  for ( i = 0; i < 4; i = v2 )
  {
    v2 = i + 1;
    v3 = 16 * (i + 1);
    if ( v0[1] < v3 )
      runtime_panicSliceAlen(v6, v9);
    v4 = i;
    v5 = 16 * i;
    if ( v5 > v3 )
      runtime_panicSliceB(v6, v9);
    v32 = v4;
    runtime_stringtoslicebyte(0, *v0 + (((int)(v5 - v3) >> 31) & v5), v3 - v5, v12, v20, v25);
    main_encryptPart(
      v32,
      v13,
      v21,
      v26,
      main_key,
      dword_81856B4,
      dword_81856B8,
      main_iv,
      dword_81856A4,
      dword_81856A8,
      v29);
    if ( v32 >= 4 )
      runtime_panicIndex(v6, v9);
    v45[v32] = v29;
    v0 = v36;
  }
  main_merge(v45, 4, 4, v12, v20, v25);
  v33 = v14;
  v30 = 2 * v22;
  runtime_makeslice(&unk_80E74E0, 2 * v22, 2 * v22, v14);
  v35 = v15;
  encoding_hex_Encode(v15, v30, v30, v33, v22, v27, v28);
  runtime_slicebytetostring(0, v35, v30, v16, v23);
  v34 = v17;
  v31 = v24;
  v44[0] = (int)&unk_80E7360;
  v44[1] = (int)&off_8115798;
  v44[2] = (int)&unk_80E7360;
  v44[3] = (int)&off_81157A0;
  fmt_Fprintln(&go_itab__os_File_io_Writer, os_Stdout, v44, 2, 2);
  runtime_convTstring(v34, v31, v10);
  v42 = &unk_80E7360;
  v43[0] = (int)&off_81157A8;
  v43[1] = (int)&unk_80E7360;
  v43[2] = v11;
  fmt_Fprintln(&go_itab__os_File_io_Writer, os_Stdout, &v42, 2, 2);
  if ( v31 == 128 && (runtime_memequal(&unk_80FFFE8, v34, 128, v18), v19) )
  {
    v38[0] = (int)&unk_80E7360;
    v38[1] = (int)&off_81157B0;
    fmt_Fprintln(&go_itab__os_File_io_Writer, os_Stdout, v38, 1, 1);
  }
  else
  {
    v37[0] = (int)&unk_80E7360;
    v37[1] = (int)&off_81157B8;
    fmt_Fprintln(&go_itab__os_File_io_Writer, os_Stdout, v37, 1, 1);
  }
}
```

This is a really big mess, but we can roughly guess that `fmt_Fprint(&go_itab__os_File_io_Writer, os_Stdout, v41, 1, 1);` prints "`Enter Your Flag Here: `", while `fmt_Fscanln(&go_itab__os_File_io_Reader, os_Stdin, v40, 1, 1);` probably obtains our input and saves it to `v40`

We can see that `v40` was to set to the pointer `v8`, while `v36` was also set to the pointer `v8`. Hence, we can deduce that **`v36` points to `v40`**`v36` and that `v36[1] != 64` is probably checking for the flag length of `64 characters`

Entering 64 random characters, we get:

```
Enter your flag here: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Expected ciphertext: 20d91f642406ce17432107a0f61a5405c3b45ec744d07c2d3a19649f5ed2c5baff4d15473b92c1d00916790dd14deec77a9d413a1e2fe83f0775bd7d3c984c4c
Actual ciphertext: fa0d3d727864af52496e5b2ee5e3fffdfa0d3d727864af52496e5b2ee5e3fffdfa0d3d727864af52496e5b2ee5e3fffdfa0d3d727864af52496e5b2ee5e3fffd
Sorry, try again.
```

It seems like the flag's expected ciphertext should be `20d91f642406ce17432107a0f61a5405c3b45ec744d07c2d3a19649f5ed2c5baff4d15473b92c1d00916790dd14deec77a9d413a1e2fe83f0775bd7d3c984c4c`. 

`   encoding_hex_Encode(v15, v30, v30, v33, v22, v27, v28);` suggests that this is hex



## Solving It

Looking a bit downwards, I spot another interesting part: `main_encryptPart`

```c
for ( i = 0; i < 4; i = v2 )
  {
    v2 = i + 1;
    v3 = 16 * (i + 1);
    if ( v0[1] < v3 )
      runtime_panicSliceAlen(v6, v9);
    v4 = i;
    v5 = 16 * i;
    if ( v5 > v3 )
      runtime_panicSliceB(v6, v9);
    v32 = v4;
    runtime_stringtoslicebyte(0, *v0 + (((int)(v5 - v3) >> 31) & v5), v3 - v5, v12, v20, v25);
    main_encryptPart(
      v32,
      v13,
      v21,
      v26,
      main_key,
      dword_81856B4,
      dword_81856B8,
      main_iv,
      dword_81856A4,
      dword_81856A8,
      v29);
    if ( v32 >= 4 )
      runtime_panicIndex(v6, v9);
    v45[v32] = v29;
    v0 = v36;
  }
```

We see a `main_key` and `main_iv`, which is probably the **key and IV for our AES cipher**.

Ignoring the `runtime_panicSliceAlen` golang functions, we can deduce what this for loop does:

- `v0` = `v36`, which is our input string
- `runtime_stringtoslicebyte(0, *v0 + (((int)(v5 - v3) >> 31) & v5), v3 - v5, v12, v20, v25);` basically **slices the string into a group of 16** (E.g `[0:16]`, [`16:32`]...)
-  Each group of 16 is then sent to `main_encryptPart`
- The for loop is repeated **4 times, encoding 4 groups of 16 in total**

I decided to take a look at `main_encryptPart` to see if there are any modifications made to a normal AES cipher.

```c
int main_encryptPart()
{
  int v1; // [esp+8h] [ebp-30h]
  void *retaddr; // [esp+38h] [ebp+0h] BYREF

  if ( (unsigned int)&retaddr <= *(_DWORD *)(*(_DWORD *)(__readgsdword(0) - 4) + 8) )
    runtime_morestack_noctxt();
  runtime_makechan(&unk_80E49A0, 1);
  runtime_newproc(44, (char)&off_8100154);
  return v1;
}
```

I can see that `newproc` seems to be calling a `main_encryptPart_func1` (`&off_8100154` == `main_encryptPart_func1`)

**<u>Note:</u>** During the actual competition, I got lucky and found `main_encryptPart_func1` by just searching for `encrypt` in the functions list, before working backwards to figure out how it is called

Looking at `main_encryptPart_func1`, it basically does nothing in particular and calls `main_aesEncrypt`:

```c
_DWORD *__cdecl main_aesEncrypt(int a1, _DWORD *a2, int a3, int a4, int a5, int a6)
{
  _DWORD *result; // eax
  int v7; // [esp+4h] [ebp-24h]
  _DWORD *v8; // [esp+4h] [ebp-24h]
  int v9; // [esp+Ch] [ebp-1Ch]
  int v10; // [esp+14h] [ebp-14h]
  void *retaddr; // [esp+28h] [ebp+0h] BYREF

  if ( (unsigned int)&retaddr <= *(_DWORD *)(*(_DWORD *)(__readgsdword(0) - 4) + 8) )
    runtime_morestack_noctxt();
  crypto_aes_NewCipher(a4, a5, a6);
  if ( v10 )
  {
    runtime_newobject(&unk_80E9880, v7);
    result = v8;
    v8[1] = 11;
    *v8 = &unk_80F8E12;
  }
  else
  {
    runtime_makeslice(&unk_80E74E0, a2, a2);
    crypto_cipher_NewCBCEncrypter(v9);
    MEMORY[0x14]();
    result = a2;
  }
  return result;
}
```

`main_aesEncrypt` doesn't seem to do anything in particular either, and simply creates an AES cipher using ` crypto_aes_NewCipher(a4, a5, a6);`, and using **CBC Mode** via `crypto_cipher_NewCBCEncrypter(v9);`



### Solve Script

We can easily script this in python to decode the the ciphertext

```python
from Crypto.Cipher import AES
import hashlib
import base64


key = b'mysupersecurekey'
IV = list('mysupersecureiv ')
current = ""
IV[15] = chr(0) #If the IV is not 16 bytes, it is normally padded with \x00 (but I did bruteforce through the entire ASCII table and this is the correct byte)
IV = ''.join(IV)
IV = IV.encode()

decode = "20d91f642406ce17432107a0f61a5405c3b45ec744d07c2d3a19649f5ed2c5baff4d15473b92c1d00916790dd14deec77a9d413a1e2fe83f0775bd7d3c984c4c"
contents = b""
for x in range(0, int(len(decode)/2), 1):
    contents += int(decode[x*2:x*2+2], 16).to_bytes(1, byteorder='big')

for x in range(0, len(contents), 16):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(contents[x:x+16]).decode()
    print(decrypted)
```

And we get the flag:

```
CTFSG{t0d@y_1_1E
@rnT_hum@ns_c@nt
_multit@sk_BUT_c
0mput3rs_c@n_d0}
```



------

## Learning Points

- Golang RE is about ignoring the **huge amount of junk** and focusing on what you want
- **AES encrypts/decrypts differently** if you **split it into sections to encrypt/decrypt**
# gogo [110 Points - 200 Solves]

```
Hmmm this is a weird file... enter_password. There is a instance of the service running at mercury.picoctf.net:6516.
```

Looking at file, it is an ELF32, we are greeted with the text: "`Enter Password: `" when we run the program

 Let's look at `main_main` first:

```c
void __cdecl main_main()
{
  __interface_{} typa; // [esp+0h] [ebp-58h]
  __interface_{} typb; // [esp+0h] [ebp-58h]
  __interface_{} typc; // [esp+0h] [ebp-58h]
  __interface_{} typd; // [esp+0h] [ebp-58h]
  __interface_{} type; // [esp+0h] [ebp-58h]
  __interface_{} typf; // [esp+0h] [ebp-58h]
  runtime__type_0 *typ; // [esp+0h] [ebp-58h]
  __interface_{} typg; // [esp+0h] [ebp-58h]
  void *siz; // [esp+4h] [ebp-54h]
  int32 siza; // [esp+4h] [ebp-54h]
  void *sizb; // [esp+4h] [ebp-54h]
  int32 sizc; // [esp+4h] [ebp-54h]
  bool _r1; // [esp+8h] [ebp-50h]
  bool _r1a; // [esp+8h] [ebp-50h]
  error_0 err; // [esp+Ch] [ebp-4Ch]
  error_0 erra; // [esp+Ch] [ebp-4Ch]
  error_0 errb; // [esp+Ch] [ebp-4Ch]
  string v17; // [esp+14h] [ebp-44h]
  string v18; // [esp+14h] [ebp-44h]
  string v19; // [esp+14h] [ebp-44h]
  __int32 v20; // [esp+1Ch] [ebp-3Ch]
  __int32 v21; // [esp+1Ch] [ebp-3Ch]
  __int32 v22; // [esp+1Ch] [ebp-3Ch]
  string *_k; // [esp+20h] [ebp-38h]
  string *_currPasswd; // [esp+24h] [ebp-34h]
  __interface_{} a; // [esp+28h] [ebp-30h] BYREF
  string *v26; // [esp+34h] [ebp-24h]
  _DWORD v27[2]; // [esp+38h] [ebp-20h] BYREF
  _DWORD v28[2]; // [esp+40h] [ebp-18h] BYREF
  __interface_{} v29; // [esp+48h] [ebp-10h] BYREF
  int32 v30; // [esp+54h] [ebp-4h]
  void *retaddr; // [esp+58h] [ebp+0h] BYREF

  while ( (unsigned int)&retaddr <= *(_DWORD *)(*(_DWORD *)(__readgsdword(0) - 4) + 8) )
    runtime_morestack_noctxt();
  runtime_newobject((runtime__type_0 *)&e, siz);
  _currPasswd = (string *)siza;
  typa.array = (interface_{} *)&aEfloatphoenici[3067];
  *(_QWORD *)&typa.len = 16LL;
  fmt_Printf(typa, 0LL, v17, v20); //Prints "Enter Password: "
  v28[0] = &unk_80E1300;
  v28[1] = _currPasswd;
  typb.array = (interface_{} *)&::a;
  typb.len = 3;
  typb.cap = (__int32)v28;
  fmt_Scanf(typb, (error_0)0x100000001LL, v18, v21); //Get input
  main_checkPassword(*_currPasswd, _r1); //check the Password?
  if ( _r1a ) //Probably success
  {
    v27[0] = &e;
    v27[1] = &main_statictmp_0;
    typc.array = (interface_{} *)v27;
    *(_QWORD *)&typc.len = 0x100000001LL;
    fmt_Println(typc, err, (__int32)v19.str);
    a.cap = (__int32)&e;
    v26 = &main_statictmp_1;
    typd.array = (interface_{} *)&a.cap;
    *(_QWORD *)&typd.len = 0x100000001LL;
    fmt_Println(typd, erra, (__int32)v19.str);
    a.array = (interface_{} *)&e;
    a.len = (__int32)&main_statictmp_2;
    type.array = (interface_{} *)&a;
    *(_QWORD *)&type.len = 0x100000001LL;
    fmt_Println(type, errb, (__int32)v19.str);
    runtime_newobject((runtime__type_0 *)&e, sizb);
    _k = (string *)sizc;
    v29.cap = (__int32)&unk_80E1300;
    v30 = sizc;
    typf.array = (interface_{} *)&::a;
    typf.len = 3;
    typf.cap = (__int32)&v29.cap;
    fmt_Scanf(typf, (error_0)0x100000001LL, v19, v22);
    main_ambush(*_k);
    runtime_deferproc(0, (int32)&o.done);
  }
  else //Probably failure
  {
    v29.array = (interface_{} *)&e;
    v29.len = (__int32)&main_statictmp_3;
    typg.array = (interface_{} *)&v29;
    *(_QWORD *)&typg.len = 0x100000001LL;
    fmt_Println(typg, err, (__int32)v19.str);
  }
  runtime_deferreturn((uintptr)typ);
}
```

We can roughly deduce that the program first prints `Enter Password: `, asks for our input into `_currPasswd` via `scanf` and then runs the function `main_checkPassword` with `_currPasswd` we keyed in to check.

Let's look at `main_checkPassword`

```c
void __cdecl main_checkPassword(string input, bool _r1)
{
  __int32 v2; // eax
  int v3; // ebx
  uint8 key[32]; // [esp+4h] [ebp-40h] BYREF
  char v5[32]; // [esp+24h] [ebp-20h]
  void *retaddr; // [esp+44h] [ebp+0h] BYREF

  while ( (unsigned int)&retaddr <= *(_DWORD *)(*(_DWORD *)(__readgsdword(0) - 4) + 8) )
    runtime_morestack_noctxt();
  if ( input.len < 32 )
    os_Exit(0);
  sub_8090B18(0, key);
  qmemcpy(key, "861836f13e3d627dfa375bdb8389214e", sizeof(key));
  ((void (*)(void))sub_8090FE0)();
  v2 = 0;
  v3 = 0;
  while ( v2 < 32 )
  {
    if ( (unsigned int)v2 >= input.len || (unsigned int)v2 >= 32 )
      runtime_panicindex();
    if ( (key[v2] ^ input.str[v2]) == v5[v2] )
      ++v3;
    ++v2;
  }
}
```

We can see a few things here:

- The length of the password is 32 bytes, since `if ( input.len < 32 ) os_Exit(0)`, and we also see the while loop iterating 32 times
- A string is copied into the `key` variable `qmemcpy(key, "861836f13e3d627dfa375bdb8389214e", sizeof(key));`
- Inside the while loop, our input is xored against this `key` and compared against `v5`, which is presumably an **encoded version of the password**

Unfortunately, we can't seem to find where `v5` is, but not to worry, we can open it in `gdb` to look at the value.

I quickly located where the xoring and comparison are being done in assembly. Looking at `bl`, it does indeed store an encoded byte of the flag in each iteration.

```assembly
movzx   esi, [esp+eax+44h+key] ; key
xor     ebp, esi        ; xor it with input and store into ebp
movzx   esi, [esp+eax+44h+var_20]
xchg    eax, ebp
xchg    ebx, esi
cmp     al, bl          ; al contains our input byte
xchg    ebx, esi
xchg    eax, ebp
jnz     short loc_80D4B0E
```

I then wrote a `PEDA` script to quickly find the values of `bl` in each iteration and ran it using `gdb -x enter_passwordPEDA.py`:

```python
#enter_passwordPEDA.py

peda.execute("file enter_password")
peda.set_breakpoint("0x80d4b30")
peda.execute("run < " + "<(python -c 'print(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\")')")
password = []
for x in range(0, 32):
    bl = peda.getreg('ebx')
    password.append(bl)
    peda.execute("c")

print(password) #This prints out the bytes in decimal
```

And we get the output:

```
[74, 83, 71, 93, 65, 69, 3, 84, 93, 2, 90, 10, 83, 87, 69, 13, 5, 0, 93, 85, 84, 16, 1, 14, 65, 85, 87, 75, 69, 80, 70, 1]
```

Xoring this with the string `861836f13e3d627dfa375bdb8389214e` (choose `UTF-8` in cyberchef), we get the password:

```
reverseengineericanbarelyforward
```

When we enter this into the remote, we are greeted with:

```
=========================================
This challenge is interrupted by psociety
What is the unhashed key?
```

Keying the hashed key `861836f13e3d627dfa375bdb8389214e` into an online hashcracker, we get: `goldfish`, and then we get the flag:

```
picoCTF{p1kap1ka_p1c001b3038b}
```


# Easy as GDB [143 Solves] - 160 Points

```
The flag has got to be checked somewhere... File: brute
```

We are given the file `brute`, which is an ELF32

Running it, we are greeted with the following:

```bash
./brute
input the flag: fcsdifhsidhfgbsd
checking solution...
Incorrect.
```

I first threw the file into IDA and looked at a function which seemed to be the main function:

```c
int mainISHthing() //I named it this
{
  char *v0; // eax
  int v2; // [esp-8h] [ebp-20h]
  int v3; // [esp-4h] [ebp-1Ch]
  char *s; // [esp+4h] [ebp-14h]
  size_t n; // [esp+8h] [ebp-10h]
  char *src; // [esp+Ch] [ebp-Ch]

  s = (char *)calloc(0x200u, 1u);
  printf("input the flag: ");
  fgets(s, 512, stdin);
  v0 = (char *)strnlen(byte_2008, 512, v2, v3);
  src = (char *)sub_82B(v0, (size_t)v0);
  sub_7C2((int)src, 1u, 1);
  if ( sub_8C4(src, n) == 1 )
    puts("Correct!");
  else
    puts("Incorrect.");
  return 0;
}
```

Looking around, we see the string `checking solution...` in `sub_8C4()`. Hence we can deduce that that is the method for checking our flag

```c
int __cdecl sub_8C4(char *src, size_t n)
{
  int v3; // [esp+0h] [ebp-18h]
  size_t i; // [esp+4h] [ebp-14h]
  char *dest; // [esp+8h] [ebp-10h]
  char *v6; // [esp+Ch] [ebp-Ch]

  dest = (char *)calloc(n + 1, 1u);
  strncpy(dest, src, n);
  sub_7C2((int)dest, n, -1);
  v6 = (char *)calloc(n + 1, 1u);
  strncpy(v6, byte_2008, n);
  sub_7C2((int)v6, n, -1);
  puts("checking solution...");
  v3 = 1;
  for ( i = 0; i < n; ++i ) //n is the length of the flag
  {
    if ( dest[i] != v6[i] )
      return -1;
  }
  return v3;
}
```

We can deduce that `dest` is probably our input, and `v6`, which is copied from `byte_2008` and contains quite a lot of data, is the **encoded flag** (since `byte_2008` does not contain the flag :sweat:) !

Let's jump into `gdb` to see how our input is being compared to the encoded flag.

After stepping through for quite sometime, I reached the place where the comparison was being done (`if ( dest[i] != v6[i] )`) 

```assembly
#Checking solution function
   0x56555986:  mov    eax,DWORD PTR [ebp-0x14]
   0x56555989:  add    eax,ecx
   0x5655598b:  movzx  eax,BYTE PTR [eax]
=> 0x5655598e:  cmp    dl,al ;al(eax) is the encrypted flag, dl(edx) is our encoded input
   0x56555990:  je     0x5655599b
   0x56555992:  mov    DWORD PTR [ebp-0x18],0xffffffff
   0x56555999:  jmp    0x565559a7
   0x5655599b:  add    DWORD PTR [ebp-0x14],0x1
```

*Note that none of these code were recognised as functions, so you have to use `x/100i <address>` to disassemble this address as assembly instructions*

Looking at `dl` , I couldn't quite figure out how our input was being encoded, and trying different combinations didn't really seem to help. However, I did find that by typing `picoCTF{.*}`, `al==dl` for the **first 8 iterations**, which is to be expected.

**<u>Note:</u>** We can also deduce that `n` is the length of our flag, and inside `gdb`, I set a breakpoint at:

```assembly
  0x565559a2:  cmp    eax,DWORD PTR [ebp+0xc]
```

Which revealed that the length is `30`



## Bruteforcing The Flag

At this point, I gained inspiration from the name of the file: `brute` (and the hints).

As the challenge strongly suggests, we are probably supposed to be **brute-forcing the flag**. How can we do this? By using **gdb-python**!

However, I opted to use `PEDA-python` as it seemed much easier to use compared to `gdb-python`.

I quickly wrote a python script which will set a breakpoint at `0x5655598e`. It will try a character for a position of the flag, see if `al==dl`, and if not, try another character for the same position until it gets a match. Then, move on to the next position of the flag to brute that position's character

```python
flag = list("picoCTF{BBBBBBBBBBBBBBBBBBBBB}")

peda.execute('file brute')
peda.set_breakpoint('0x5655598e')
peda.execute("run < " + "<(python -c 'print(\"" + ''.join(flag) + "\")')") #This is a trick used to send input via stdin in GDB (https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection)
#Using run means that we don't have the initial breakpoint and end up at our first bp
for y in range(0, len(flag), 1):
    al = peda.getreg("eax")
    dl = peda.getreg("edx")
    if (al == dl):
        print("pass : " + str(y+1))
        peda.execute("c")
    else:
        for x in range(48, 123, 1):
            if (x <= 57 or (x >= 64 and x <= 90) or (x == 95) or (x >= 97 and x <= 122) ): #See note below
                character = chr(x)
                flag[y] = character
                peda.execute("run < " + "<(python -c 'print(\"" + ''.join(flag) + "\")')")
                for continueTill in range(y):
                    peda.execute("c")

                al = peda.getreg("eax")
                dl = peda.getreg("edx")
                if (al == dl):

                    print("found character " + character + " for position " + str(y))
                    peda.execute("c")
                    break
    print(''.join(flag))
```

**<u>Note:</u>** It seems like trying non-alphanumeric characters other than `_` breaks the program,I am not too sure why.

After running it using `gdb -x <filename>` and waiting a really long time, we get the flag:

```
picoCTF{I_5D3_A11DA7_6aa8dd3b}
```



## Learning Points

- GDB/PEDA Python is goodie!
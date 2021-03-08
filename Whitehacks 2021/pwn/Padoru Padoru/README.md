# Padoru Padoru

Let's wrap some gifts to prepare for xmas 2021! ʕ0ᴥ0ʔ

Interact with the service using `chals.whitehacks.ctf.sg 20001` to get started!

Note: this challenge requires `libssl` to be installed to run.

**Files**: [flag.wrapped](https://api.whitehacks.ctf.sg/file?id=cklta9jty0qdw080717chzwsr&name=flag.wrapped) [padoru](https://api.whitehacks.ctf.sg/file?id=cklta9k0f0qeg08075z0q1ngd&name=padoru)

```sh
$ xxd flag.wrapped
00000000: 393e 151a 3fae e6c6 a7d8 57fd 62a0 f106  9>..?.....W.b...
00000010: 5e41 b492 26a7 ea63 ecd6 0a34 25fc 5ff3  ^A..&..c...4%._.
00000020: 1c7b bf97 255e f8a4 8938 0600 e4f9 ee0e  .{..%^...8......
$ checksec padoru
[*] 'padoru'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000) # !
```

## Understanding

`main()` is very simple to read with a few added labels:

```c
char keydata[0x20]; // .bss:602200
void setup_IO() {
    /* handle setvbuf stuff */
}
void init_key() { 
  FILE *stream = fopen("/home/padoru/aeskey", "r");
  if ( !stream ) exit(1);
  return fread(keydata, 1uLL, 0x20uLL, stream);
}
void banner() {
  // print out a very large, coloured introduction banner
}
int main() {
  char s[128]; // [rsp+10h] [rbp-190h] BYREF
  char ptr[264]; // [rsp+90h] [rbp-110h] BYREF
  uint64_t cookie = __readfsqword(0x28u); // [rsp+198h] [rbp-8h]
    
  setup_IO();
  init_key();
  banner();
  printf("Submit your gift => ");
    
  for (int i = 0; i <= 126; ++i) {  // [rsp+8h] [rbp-198h]
    char c = _IO_getc(stdin); // [rsp+7h] [rbp-199h]
    if ( c == -1 || !c || c == '\n' ) {
      s[i] = '\0';
      break;
    }
    s[i] = c;
  }
  s[127] = '\0';

  int cryptlen = encrypt(s, strlen(s), keydata, 0LL, ptr);  // [rsp+Ch] [rbp-194h]
  puts("Received the following gift for wrapping:");
  printf(s); // format string exp
  puts("\nHere is your wrapped gift:");
  fwrite(ptr, 1uLL, cryptlen, stdout);
}
```

In short, `main()` will read up to 127 bytes of data (`s[]`) from stdin, encrypt that data into `ptr[]` with a secret key, print out `s[]` as a format string bug, and then print the encrypted output.

We're also provided with `flag.wrapped` as a file, which we'll probably need to decrypt with the key. The goal of the challenge is to make use of `"%{}$s"` format specifier to leak out the value of `keydata[]`, using it as an AES (ECB) key to decrypt `flag.wrapped`. There are a few obstacles in the challenge that make this task a little bit harder that it might otherwise be:

1.  The input for-loop stops receiving input after any `'\0'` bytes. That presents a problem, because our format string needs to put the address of `keydata` (`0x0000000000602200`) somewhere on the stack, but inserting nul-bytes is impossible. A cursory scan of the stack demonstrates that `keydata` isn't preserved on the stack either:
    ```sh
    Submit your gift => %p %p %p %p %p %p %p %p %p %p %p %p %p
    Received the following gift for wrapping:
    0x7fc7085507e3 0x7fc7085518c0 0x7fc708274224 0x29 0x9 0xa007fc700000002 0x3000000026 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x702520702520 (nil)
    ```
    The solution here is to partially write the address of `keydata+1` to a region of the stack that's _already_ `(nil)`, allowing for the full address to appear on the stack.
2.  `keydata[]` itself is intentionally (by the challenge author, that is) filled with a large number of nul-bytes. Extracting the full flag will require multiple printf leaks.

After [a lot of `printf()` hacks](padoru.py), the flag appears:

## flag

`WH2021{1abd770cdc8a_h4sh1_r3_s0r3_yo!}`

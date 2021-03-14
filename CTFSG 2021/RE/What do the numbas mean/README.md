# What do the numbas mean? [972 Points] - 13 Solves

```
Agent: "Only you can tell us what the codes mean. We have the broadcast, we have been playing to you over and over again for hours but we haven't been able to break through your programming yet. This is our last shot."
```

We are given a `whatdothenumbasmean.txt` file.

Opening it up, we are greeted with the header:

```
---------------------------IR DUMP: what_do_they_mean---------------------------
label 0:
    flag = arg(0, name=flag)                 ['flag']
    $const4.1 = const(int, 0)                ['$const4.1']
....
```

I first tried googling `IR DUMP` to figure out what this is, but with little to no success, though I did saw references to `python numbas moudle`. (After the CTF, `violenttestpen` said that it is `python code -> python bytecode -> CFG -> Numba IR -> Numba SSA -> LLVM assembly -> native assembly` and it is an `IL Debug output` from the `python numbas module`)

Looking at the first `label` of code:

```
Label 0:
    flag = arg(0, name=flag)                 ['flag']
    $const4.1 = const(int, 0)                ['$const4.1']
    $6binary_subscr.2 = static_getitem(value=flag, index=0, index_var=$const4.1, fn=<built-in function getitem>) ['$6binary_subscr.2', '$const4.1', 'flag']
    $const8.3 = const(str, C)                ['$const8.3']
    $10compare_op.4 = $6binary_subscr.2 != $const8.3 ['$10compare_op.4', '$6binary_subscr.2', '$const8.3']
    bool12 = global(bool: <class 'bool'>)    ['bool12']
    $12pred = call bool12($10compare_op.4, func=bool12, args=(Var($10compare_op.4, whatdothenumbasmean.py:26),), kws=(), vararg=None) ['$10compare_op.4', '$12pred', 'bool12']
    branch $12pred, 86, 14                   ['$12pred']
```

What this seems to do is that:

- `flag = arg(0, name=flag)  ` creates a `flag` variable
- `static_getitem(value=flag, index=0, index_var=$const4.1, fn=<built-in function getitem>)` seems to **get the character of `flag` at index `0`**
- `$10compare_op.4 = $6binary_subscr.2 != $const8.3` compares the index `0` character to "`C`"

Going down the next few labels, we see a similar pattern, with each comparing against a character, and we get the string:

```
CTFSG{<something>}
```

The next few lines are really really tedious to explain, so sit tight:

- ```python
  $98binary_subscr.5 = static_getitem(value=flag, index=slice(6, -1, None), index_var=$96build_slice.4, fn=<built-in function getitem>)
  buf = $98binary_subscr.5 #Slice out middle values of string {....} and save it to buf
  ...
  $102load_global.6 = global(len: <built-in function len>) ['$102load_global.6']
  $106call_function.8 = call $102load_global.6(buf, func=$102load_global.6, args=[Var(buf, whatdothenumbasmean.py:35)], kws=(), vararg=None) #Get length of buf
  ...
  $const108.9 = const(int, 16)             ['$const108.9']
  $110compare_op.10 = $106call_function.8 != $const108.9 ['$106call_function.8', '$110compare_op.10', '$const108.9']
  #Check that length of buf = 16
  ```

  - This basically means that there are `16` chars in the middle of `CTFSG{.*}`

- ```python
  $120load_method.1 = getattr(value=buf, attr=startswith) ['$120load_method.1', 'buf'] #Returns value of attribute startswith of object buf
  $const122.2 = const(str, th3)
  $124call_method.3 = call $120load_method.1($const122.2, func=$120load_method.1, args=[Var($const122.2, whatdothenumbasmean.py:40)], kws=(), vararg=None)
  ```

  - This seems to check that `buf` startswith the string "`th3`"
  - Hence it is now: `CTFSG{th3.....}`

- ```python
  $const132.0 = const(str, numb)
  $136compare_op.2 = $const132.0 in buf
  ```

  - This checks that the string `numb` is inside `buf`

- ```python
  label 144:
      $const144.0 = const(int, 0)              ['$const144.0']
      letters = $const144.0                    ['$const144.0', 'letters']
      $150get_iter.2 = getiter(value=buf)      ['$150get_iter.2', 'buf'] #Returns iterator of buf string (looping through?)
      $phi152.0 = $150get_iter.2               ['$150get_iter.2', '$phi152.0']
      jump 152                                 []
  label 152:
      $152for_iter.1 = iternext(value=$phi152.0) ['$152for_iter.1', '$phi152.0'] #Get next vakye
      $152for_iter.2 = pair_first(value=$152for_iter.1) ['$152for_iter.1', '$152for_iter.2']
      $152for_iter.3 = pair_second(value=$152for_iter.1) ['$152for_iter.1', '$152for_iter.3']
      $phi154.1 = $152for_iter.2               ['$152for_iter.2', '$phi154.1']
      branch $152for_iter.3, 154, 194          ['$152for_iter.3']
  label 154:
      ch = $phi154.1                           ['$phi154.1', 'ch']
      $const156.2 = const(int, 97)             ['$const156.2']
      $158load_global.3 = global(ord: <built-in function ord>) ['$158load_global.3'] #!!!!!!!
      $162call_function.5 = call $158load_global.3(ch, func=$158load_global.3, args=[Var(ch, whatdothenumbasmean.py:48)], kws=(), vararg=None) ['$158load_global.3', '$162call_function.5', 'ch']
      $168compare_op.7 = $const156.2 <= $162call_function.5 ['$162call_function.5', '$168compare_op.7', '$const156.2']
      bool170 = global(bool: <class 'bool'>)   ['bool170']
      $170pred = call bool170($168compare_op.7, func=bool170, args=(Var($168compare_op.7, whatdothenumbasmean.py:49),), kws=(), vararg=None) ['$168compare_op.7', '$170pred', 'bool170']
      $phi172.1 = $162call_function.5          ['$162call_function.5', '$phi172.1']
      branch $170pred, 172, jumpToEXITLoop                ['$170pred']
  label 172:
      $const172.2 = const(int, 122)            ['$const172.2']
      $174compare_op.3 = $phi172.1 <= $const172.2 ['$174compare_op.3', '$const172.2', '$phi172.1']
      bool176 = global(bool: <class 'bool'>)   ['bool176']
      $176pred = call bool176($174compare_op.3, func=bool176, args=(Var($174compare_op.3, whatdothenumbasmean.py:49),), kws=(), vararg=None) ['$174compare_op.3', '$176pred', 'bool176']
      branch $176pred, 178, jumpToEXITLoop                ['$176pred']
  label 178:
      jump 184                                 []
  label 180:
      jump 297                                 []
  label 184:
      $const186.2 = const(int, 1)              ['$const186.2']
      $188inplace_add.3 = inplace_binop(fn=<built-in function iadd>, immutable_fn=<built-in function add>, lhs=letters, rhs=$const186.2, static_lhs=Undefined, static_rhs=Undefined) ['$188inplace_add.3', '$const186.2', 'letters']
      letters = $188inplace_add.3              ['$188inplace_add.3', 'letters'] #inplace_add is "+=" (letters += 1)
      jump 297                                 []
  label 194:
      $const196.1 = const(int, 10)             ['$const196.1']
      $198compare_op.2 = letters != $const196.1 ['$198compare_op.2', '$const196.1', 'letters']
      bool200 = global(bool: <class 'bool'>)   ['bool200']
      $200pred = call bool200($198compare_op.2, func=bool200, args=(Var($198compare_op.2, whatdothenumbasmean.py:51),), kws=(), vararg=None) ['$198compare_op.2', '$200pred', 'bool200']
      branch $200pred, 202, 206                ['$200pred']
  ```

  - This huge chunk basically checks that the **number of lower-case characters (`97 <= x <= 122`) is `10`**
  - Looking at the 2 strings we already have: `th3` and `numb`, this means that we are still **missing `4` lowercase chars**

- ```python
  label 206:
      $const208.1 = const(int, 3)              ['$const208.1']
      $210binary_subscr.2 = static_getitem(value=buf, index=3, index_var=$const208.1, fn=<built-in function getitem>) ['$210binary_subscr.2', '$const208.1', 'buf']
      $const214.4 = const(int, 10)             ['$const214.4']
      $216binary_subscr.5 = static_getitem(value=buf, index=10, index_var=$const214.4, fn=<built-in function getitem>) ['$216binary_subscr.5', '$const214.4', 'buf']
      $218compare_op.6 = $210binary_subscr.2 != $216binary_subscr.5 ['$210binary_subscr.2', '$216binary_subscr.5', '$218compare_op.6']
      bool220 = global(bool: <class 'bool'>)   ['bool220']
      $220pred = call bool220($218compare_op.6, func=bool220, args=(Var($218compare_op.6, whatdothenumbasmean.py:55),), kws=(), vararg=None) ['$218compare_op.6', '$220pred', 'bool220']
      branch $220pred, 234, 222                ['$220pred']
  ```

  - This means that the index `3` char of `buf` must be the same as index `10` char

- ```python
  label 222:
      $const224.1 = const(int, 3)              ['$const224.1']
      $226binary_subscr.2 = static_getitem(value=buf, index=3, index_var=$const224.1, fn=<built-in function getitem>) ['$226binary_subscr.2', '$const224.1', 'buf']
      $const228.3 = const(str, _)              ['$const228.3']
      $230compare_op.4 = $226binary_subscr.2 != $const228.3 ['$226binary_subscr.2', '$230compare_op.4', '$const228.3']
      bool232 = global(bool: <class 'bool'>)   ['bool232']
      $232pred = call bool232($230compare_op.4, func=bool232, args=(Var($230compare_op.4, whatdothenumbasmean.py:55),), kws=(), vararg=None) ['$230compare_op.4', '$232pred', 'bool232']
      branch $232pred, 234, 238                ['$232pred']
  ```

  - Index `3` char of `buf` == `_`

  - ```
    CTFSG{th3_numbxx_xxxxx}
    ```

- ```python
      $const240.1 = const(int, 8)              ['$const240.1']
      $242binary_subscr.2 = static_getitem(value=buf, index=8, index_var=$const240.1, fn=<built-in function getitem>) ['$242binary_subscr.2', '$const240.1', 'buf']
      $const246.4 = const(int, 12)             ['$const246.4']
      $248binary_subscr.5 = static_getitem(value=buf, index=12, index_var=$const246.4, fn=<built-in function getitem>) ['$248binary_subscr.5', '$const246.4', 'buf']
      $250compare_op.6 = $242binary_subscr.2 != $248binary_subscr.5 ['$242binary_subscr.2', '$248binary_subscr.5', '$250compare_op.6']
      bool252 = global(bool: <class 'bool'>)   ['bool252']
      $252pred = call bool252($250compare_op.6, func=bool252, args=(Var($250compare_op.6, whatdothenumbasmean.py:57),), kws=(), vararg=None) ['$250compare_op.6', '$252pred', 'bool252']
      branch $252pred, 270, 256                ['$252pred']
  ```

  - Index `8` char == index `12` char

- ```python
      $const258.1 = const(int, 8)              ['$const258.1']
      $260binary_subscr.2 = static_getitem(value=buf, index=8, index_var=$const258.1, fn=<built-in function getitem>) ['$260binary_subscr.2', '$const258.1', 'buf']
      $const262.3 = const(str, @)              ['$const262.3']
      $264compare_op.4 = $260binary_subscr.2 != $const262.3 ['$260binary_subscr.2', '$264compare_op.4', '$const262.3']
      bool266 = global(bool: <class 'bool'>)   ['bool266']
      $266pred = call bool266($264compare_op.4, func=bool266, args=(Var($264compare_op.4, whatdothenumbasmean.py:57),), kws=(), vararg=None) ['$264compare_op.4', '$266pred', 'bool266']
      branch $266pred, 270, 274                ['$266pred']
  ```

  - Index `8` char == `@`

  - ```
    CTFSG{th3_numb@x_x@xxx}
    ```

- ```python
      $274load_global.0 = global(ord: <built-in function ord>) ['$274load_global.0']
      $const278.2 = const(int, 14)             ['$const278.2']
      $280binary_subscr.3 = static_getitem(value=buf, index=14, index_var=$const278.2, fn=<built-in function getitem>) ['$280binary_subscr.3', '$const278.2', 'buf']
      $282call_function.4 = call $274load_global.0($280binary_subscr.3, func=$274load_global.0, args=[Var($280binary_subscr.3, whatdothenumbasmean.py:61)], kws=(), vararg=None) ['$274load_global.0', '$280binary_subscr.3', '$282call_function.4']
      $const284.5 = const(int, 48)             ['$const284.5']
      $286compare_op.6 = $282call_function.4 != $const284.5 ['$282call_function.4', '$286compare_op.6', '$const284.5']
      bool288 = global(bool: <class 'bool'>)   ['bool288']
      $288pred = call bool288($286compare_op.6, func=bool288, args=(Var($286compare_op.6, whatdothenumbasmean.py:61),), kws=(), vararg=None) ['$286compare_op.6', '$288pred', 'bool288']
      branch $288pred, 292, 296                ['$288pred']
  ```

  - Index `14` char == `0`

  - ```
    CTFSG{th3_numb@x_x@x0x}
    ```

- ```python
      $296load_global.0 = global(crc32: CPUDispatcher(<function crc32 at 0x01EAA538>)) ['$296load_global.0']
      $300call_function.2 = call $296load_global.0(flag, func=$296load_global.0, args=[Var(flag, whatdothenumbasmean.py:26)], kws=(), vararg=None) ['$296load_global.0', '$300call_function.2', 'flag']
      $const302.3 = const(int, 3476224294)     ['$const302.3']
      $304compare_op.4 = $300call_function.2 == $const302.3 ['$300call_function.2', '$304compare_op.4', '$const302.3']
      $306return_value.5 = cast(value=$304compare_op.4) ['$304compare_op.4', '$306return_value.5']
      return $306return_value.5                ['$306return_value.5']
  ```

  - The `CRC32` of the **entire flag `CTFSG{...}`** is == `3476224294`

At this point, our flag is:

```
CTFSG{th3_numb@x_x@x0x}
```

where `x` is a lowercase letter of ASCII `97 <= x <= 122`. Hence, we can easily bruteforce the 4 lower case letters and compare it to the given `CRC32` since there are only `26^4 = 456976` combinations at most.

Thus we get the flag:

```
CTFSG{th3_numb@s_m@s0n}
```



------

## Learning Points

- Patience is a virtue
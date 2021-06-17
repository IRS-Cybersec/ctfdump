# BCACTF Trailblazer [27 Solves] - 450 Points

```
To boldly go where no one has gone before...
```
## Initial Analysis
We are given a `trailblazer` ELF64.
Looking at the `main` function initially, we see it calling a `check_flag` function with out input (which is the flag)

## check_flag function
Unfortunately, IDA was unable to render the `check_flag` function using pesudocode or graph view, and we will soon see why.
The check_flag function passes our input to  `strlen` to check and see if `len(inputFlag) === 47`

```assembly
0x0000000000401203 <+12>:    mov    QWORD PTR [rbp-0x28],rdi ;move input which is stored in the rdi register as a parameter into rbp-0x28
0x0000000000401207 <+16>:    mov    rax,QWORD PTR [rbp-0x28] ;move input into rax
0x000000000040120b <+20>:    mov    rdi,rax ;move input into rdi and pass into strlen
0x000000000040120e <+23>:    call   0x401080 <strlen@plt>
0x0000000000401213 <+28>:    mov    DWORD PTR [rbp-0x14],eax
0x0000000000401216 <+31>:    cmp    DWORD PTR [rbp-0x14],0x2f ; check that len = 0x2f = 47
```

Afterwards, it passes the address of a function into `perms()`
```assembly
0x0000000000401223 <+44>:    mov    QWORD PTR [rbp-0x10],0x401262 ;address of a function (0x401262) moved into rbp-0x10
0x000000000040122b <+52>:    mov    rax,QWORD PTR [rbp-0x28] ;input moved into rax
0x000000000040122f <+56>:    mov    QWORD PTR [rbp-0x8],rax ;input moved into rbp-0x8
0x0000000000401233 <+60>:    mov    rax,QWORD PTR [rbp-0x10] ;function address moved into rax
0x0000000000401237 <+64>:    mov    rdi,rax ;address of function passed to perms
0x000000000040123a <+67>:    call   0x401196 <perms>
0x000000000040123f <+72>:    test   eax,eax
```
Inside `perms`, it calls `mprotect()` to give write access to the function address.
This suggests that it is **probably a decode the code with your input** challenge since our input (the flag), is used to **change the code in this function** later on in some way.

Moving on, then function then does a xor operation between the **first 8 bytes of our input** and the **first 8 bytes of the function**
- This decodes the **first 8 bytes of the function** `+107 to +115`
- By entering `bcactf{A....}`, we can see a glimpse of the correct decoded code as the first 7 bytes are bound to be correct, though the last byte is probably wrong which causes the code to be malformed

```assembly
0x0000000000401243 <+76>:    mov    edi,0x402008
0x0000000000401248 <+81>:    call   0x401070 <puts@plt>
0x000000000040124d <+86>:    mov    eax,0x1
0x0000000000401252 <+91>:    jmp    0x4011f5 <perms+95>
0x0000000000401254 <+93>:    mov    rax,QWORD PTR [rbp-16] ;Base of the function - in "rax"
0x0000000000401258 <+97>:    mov    rbx,QWORD PTR [rbp-8] ;Base of our input - in "rbx"
0x000000000040125c <+101>:   mov    rdx,QWORD PTR [rbx] ;Move 8 bytes of our input into rdx
0x000000000040125f <+104>:   xor    QWORD PTR [rax],rdx ;Xor 8 bytes of our input with 8 bytes of the function

;First 8 bytes of the decoded function (107-115)
;=====
0x0000000000401262 <+107>:   mov    rdx,QWORD PTR [rbx+8] ;Move next 8 byte of input into rdx
0x0000000000401266 <+111>:   xor    QWORD PTR [rax+0x27],rdx 
;=====
;Malformed byte, because bcactf{x, the x (8th byte) is a malformed byte
;Correct: xor QWORD PTR [rax+8], rdx
```

We can guess that this code probably continues on in a similar pattern, where the next **8 bytes of our input** are **xored with the next 8 bytes of the encoded function to create another 8 bytes of the encoded function**
So the first decoded 8 bytes of the decoded function should be:

```assembly
mov rdx,QWORD PTR [rbx+8]
xor QWORD PTR [rax+8], rdx ;The correct decoded instruction
```
And the next 8 bytes will be:
```assembly
mov rdx,QWORD PTR [rbx+16]
xor QWORD PTR [rax+16], rdx
```



## Solution

Brute-forcing every single character of the flag will take too long. Instead since we know that our input is xored with the encoded function bytes, we have this relationship:
`Encoded Function Bytes ^ Input = Expected Decoded Function Bytes`
Thus, we can simply **xor our expected bytes with the encoded bytes** to get the flag!

Testing this on the first 8 bytes in python, we get the first part of the flag: `bcactf{n`. I then proceeded to obtain all the `Encoded Function Bytes` as well as the `Expected Decoded Function Bytes` by **assembling the expected instructions using `pwntools.asm()`** [[Python Script Here](trailblazerDecode.py)]

<u>**Note 1:**</u> We can deduce that the last instruction chunk should be only **7 bytes** (since the input length is `47 bytes`). And since it is the end of a function, we can deduce it is a **<u>function epilogue</u>** (accompanied with a **return value of 0 since that is what the main function is expecting**)

- It needs to be `eax` instead if not the last chunk won't be 7 bytes

```assembly
mov eax, 0
leave
ret
```

**<u>Note 2:</u>** You can obtain the `Encoded Function Bytes` by using `Telescope` on `rbp-16`. However, these bytes are in **little-endian**, so do convert them to **big-endian** when xoring it with the `Expected Decoded Function Bytes`

Hence the flag we get is:

```
bcactf{now_thats_how_you_blaze_a_trail_8ge52y9}
```



## Learning Points

1. Dealing with code **encoded using the correct input**

   
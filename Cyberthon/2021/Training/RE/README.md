# Cyberthon 2021 RE Training Challenges

*I will only be providing a short TLDR for each challenge*

------

## Number Game 

```
I've turned a number game I used to play in primary school into a reverse engineering problem. Can you reverse engineer the algorithm in the pyc file and figure out how to decrypt the flag?

Concept(s) Required:
- Python
- pyc format
```

We are given `flag.txt.encrypted` and `number_game`

- `number_game` is a `.pyc` file, and we can decompile it using `uncompyle6`
- The code basically:
  - Converts each character of the flag into its decimal value (padded to 3 values)
  - Encodes the data by appending the **number of occurrences** of **repeated decimals** **infront of the decimal** (this is repeated 24 times)
  - The data is then written to `flag.txt.encrypted`
- We can write a [python script](NGdecode.py) to decrypt it

------

## Super Secure Sipher 

```
Not again? Seems like this flag has been encrypted by a Java program. Let's write a script to decrypt it!

Concept(s) Required:
- Reversing Java class files
- Properties of XOR
```

We are given a `flag.txt.out` and `SuperSecureSipher.class`

- We can decompile the Java class file using [online decompilers](http://www.javadecompilers.com/)
- We see functions such as `encrypt`, `writeToFIle` and more
- Focusing on `encrypt`:
  - It first generates a **random int `0 <= x <= 256`** by xoring the previous number it got from a random number generator 256 times
  - It iterates through the flag and saves an int to `n2`
  - In the next for loop, each character of the flag (till the 2nd last character) is xored by the previous value of `n3` and `n2`
  - We can write the following [python script](SSSDecode.py) to decode it

------

## Master Rev

```
Now it's time to learn to read raw x64 assembly. Can you reverse engineer the attached program to figure out the correct input?

Note: The flag format is CTFSG{correct input}

Concept(s) Required:
- x64 assembly
```

We are given `reverse.asm`

- Unfortunately we can't compile it as some stuff is missing, so we will have to analyse it statically
- We first see that input is read via `scanf` and it is passed as a parameter to `checkFlag` via the register `rdi`
- It then iterates through a string `3698143809343140973 ` and `118` (in **decimal form**) character by character
  - In each iteration, it compares the character to a **specific offset position of our input string** and our input string is also offset by decimal value +3
  - We can write a simple python script to reverse this process

**<u>Note:</u>** The offsetting is our input string. Hence, when reversing the process, we have to go through the in-built string char by char and place it at the appropriate offset to get the right input.

**<u>Note 2:</u>** The **decimal string** can be converted to a string by first **converting it to hex** and then **converting it to ASCII**

------

## Beep Boop

```
What the heck? This binary seems impossible to analyze statically (by just reading the disassembly). Is there another type of analysis that we can use?

Hint 1: You don't need to deobfuscate anything
Hint 2: No side-channel attacks required.

Concept(s) Required:
- Executable Packing
- Dynamic Analysis

Useful tools:
- GDB
```

We are given `beepboop`

- It is packed using `upx`. So we have to unpack it using `upx -d beepboop`
- Looking at it in IDA, we see that the binary is obfuscated using `movfuscator`
- At the challenge hints, we need not try not to deobfuscate anything and should open it in `gdb` instead
- In `gdb`, the program keeps stopping as it receives `SIGSEGV` signals. We have to modify the **GDB Signal handlers** such that it will not stop when it receives a `SIGSEGV`, and that this signal is also **passed to the program since `movfuscator` needs it apparently**. 
  - `handle SIGSEGV pass`
  - `handle SIGSEGV nostop`
  - `handle SIGILL pass`
  - `handle SIGILL nostop`
- With that, we can now run the program. After stepping through a lot using `ni`, the flag can eventually be found in one of the registers.

------

## Prove Your Worth

```
Okay, prove your worth as a reverse engineer by reversing all three levels. The binary given to you contains a placeholder flag. You should send your input to our network service for the actual flag.

Interact with the service at:
3qo9k5hk5cprtqvnlkvotlnj9d14b7mt.ctf.sg:40101

Hint 1: I highly recommend using pwntools to send your input
Hint 2: Mind your input for level 2 :)

Concept(s) Required:
- x64 Assembly

Useful tools:
- Ghidra
- IDA
```

We are given the binary `proveyourworth`

- There are 3 levels, simply read and understand what input each level wants
- Solve script available [here](proveyourworthSend.py). <u>Note:</u> there **should not be any `\n` after each line** as the **next scanf** will read the `\n` and effectively **read nothing**


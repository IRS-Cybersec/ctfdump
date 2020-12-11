---
typora-root-url: ./
---

# Voices in the head

### Forensics - 1692 Points - 26 solves

## Description

We found a voice recording in one of the forensic images but we have no clue what's the voice recording about. Are you able to help?

Hint:
Xiao wants to help. Will you let him help you?



## Understanding the Challenge

A voice recording, a .wav file... Hmm, this could potentially involve SSTV, or steganography.



The hint: **Xiao**. This points to Xiao steganography, which is a free tool used to hide secret files in BMP images or WAV files. So we're probably looking for a hidden file.



## Solution

#### Analysing the audio file

Since it is a .wav file, we think it could likely be a spectrogram.

Opening the file in Audacity, we get this:

![](/audacity.PNG)



And we set the mode to Spectrogram...

<img src="/audacitysetting.png" style="zoom: 80%;" />



which yields this...

![](/spectrogram.PNG)



`aHR0cHM6Ly9wYXN0ZWJpbi5jb20vakVUajJ1VWI=` --> a Base64 text.

Converting this Base64 to text (using CyberChef),
we obtain a pastebin link:

https://pastebin.com/jETj2uU

---

In the pastebin link, there was this chunk of text:

`++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++++++.------------.+.++++++++++.----------.++++++++++.-----.+.+++++..------------.---.+.++++++.-----------.++++++.`

At first, we suspected it was a morse code, but thought it was unlikely because of the +++, >>> and [ ].

With further research, we realised this was a Brainfuck language.

> Brainfuck was developed in 1993. It consists of eight simple commands and an instruction pointer. notable for its minimalism. Its name aptly describes the language as something complicated and unusual, exceeding the limits of one's understanding. Not intended for practical use, but to challenge and amuse programmers, like you and me!

Certainly, we were intrigued by this language!



Decrypting this Brainfuck language to text using [dcode.fr](https://www.dcode.fr/brainfuck-language), yields `'thisisnottheflag'`.

We thought this was a troll, as is with typical challenges when the "flags" are intentionally planted to be found easily, but are just trolls.

But at the same time we felt that this was quite a bit of work to do to get this result, so somehow this result could potentially be useful. But for what? 

**_What a brainfuck! we thought._**

---

#### A step closer... Or so, we hope.

We pondered for a bit, and went looked at the challenge hint. _Xiao_, hmm...

Then, realising this had to be referring to Xiao steganography, we opened the original .wav file in the program Xiao steganography.

Indeed, there was a .zip file hidden inside, and we extracted it, _unsuccessfully_. The extracted .zip file appears to be corrupted when we tried to open it.



![](/hiddenzipfile.png)



After repeated attempts, we wondered if a password was needed to extract the .zip file.

Connecting the dots, we tried '**thisisnottheflag**', obtained from earlier, as the password.

**_Success! The extracted zip file is no longer corrupted._**

---

#### Going right in

In the zip file lies a .docx file, which required a password to be extracted. Unfortunately, 'thisisnottheflag' was not the password this time.



![](/inthezipfile.png)



Wonder what could be the password this time round?



Well, as always, one should always check the zip file or .docx itself for potential clues.

We opened the zip file with 7zip, and then the properties of **This is it.docx**.

<img src="/docxproperties.png" style="zoom:67%;" />



Note that under Comment, there is govtech-csg{Th1sisn0ty3tthefl@g}. We thought this was the flag, because of the govtech-csg{...} format. Yet the text says it is not the flag.



**Another way of obtaining this "flag" was running `strings` on the zip file using the Linux shell.** (but 7zip OP :>)



Was this just a troll? No, it ain't. Turns out, this is the password to extracting the .docx file:



<img src="/flag.PNG" style="zoom:67%;" />



Here lies the flag! _and a nice clue to forensic-challenge-3 too_.



## Flag

```
govtech-csg{3uph0n1ou5_@ud10_ch@ll3ng3}
```



## But Wait!

It doesn't end here, there's still something more to this challenge!

<img src="/flagclue.png" style="zoom:67%;" />

Selecting the text with a mouse, or CTRL + A to select all, reveals a line of text hidden, in white colour, which wasn't visible in the earlier picture. Putting the text colour to black reveals `"The attacker like[s] to use Bifid Cipher"`, most likely a hint for _forensic-challenge-3_ too.



## Learning Points

- 

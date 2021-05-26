# CDDC 2020: Warp Gate 3

## Wanna PK?

***His name is Red, he is strong and muscular.***

***I heard that the CTO of UnduplicitousCorp is a big fan of him.***

____

We are given a file called `How_can_I_fight`. Doing a `file` shows that it is a ZIP file.

We can use `unzip` on the file to obtain the following.

```
dummy.pdf
pdf-sample.pdf
pdf-test.pdf
pdfurl-guide.pdf
```

However, there was nothing else to look at, so we fired up `binwalk` to see what's going on.

```bash
$binwalk How_can_I_fight

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v2.0 to extract, compressed size: 34029, uncompressed size: 240655, name: dummy.pdf
34068         0x8514          Zip archive data, at least v2.0 to extract, compressed size: 122001, uncompressed size: 329099, name: fw9.pdf
156106        0x261CA         Zip archive data, at least v2.0 to extract, compressed size: 15206, uncompressed size: 186536, name: pdf-sample.pdf
171356        0x29D5C         Zip archive data, at least v2.0 to extract, compressed size: 25675, uncompressed size: 164375, name: pdf-test.pdf
197073        0x301D1         Zip archive data, at least v2.0 to extract, compressed size: 83316, uncompressed size: 292081, name: pdfurl-guide.pdf
280435        0x44773         Zip archive data, at least v2.0 to extract, compressed size: 105, uncompressed size: 138, name: Question
280957        0x4497D         End of Zip archive
```

Hold on. There are two more files not extracted from the ZIP archive, namely `fw9.pdf` and `Question`.

After some testing with HxD, we realised that there were multiple `PK` headers within the ZIP file, and we separated them into different files. Opening it reveals the hidden two files.

But, what else can we do?

Using HxD again with Notepad++, we discovered that all 5 PDF files contain this text in one of the elements:

```
 Hello if you find this message, you are a genius!(X/5)
```

This is then followed by a `START>>` and then a long block of data that does not seem to belong to a PDF file, and then `<<END`.

We then did a `file` check on `Question`, and it came back as a bitmap image.

Opening it with HxD reveals that much of the file was missing.

We then joined up each and every block of data found from the 5 different PDF files in the order given from the message above.

This gave us an image file with the flag. (Not sure what happened to the top of the image.)

![Flag](Flag.png)



### Flag

________

```
CDDC20{Take_my_hand_my_friend!}
```



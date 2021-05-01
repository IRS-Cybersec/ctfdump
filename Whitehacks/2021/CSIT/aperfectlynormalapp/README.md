# perfectlynormalapp (A) - 495 points (8 solves)

```
Two flags have been hidden in this Android Application.

The first flag is hidden somewhere in the Java code, and requires the reversal of a simple ciphering function.

The second flag requires an understanding of the JNI calls involved and the native code called in order to decrypt the hidden flag.
```

We are given an `.apk`! Let's start by first decompiling it using `jadx`

We can quickly identify the part of the source code of itnerest: `com.ima.perfectlynormalapp`. We can deduce that `FirstFragment` is probably meant for the 1st flag, and `SecondFragment` is meant for the 2nd flag. Let's take a look at `FirstFragment` first.



## Analysis of Code

Scrolling around, we don't see anything interesting. However we do notice something:

```java
/* JADX WARNING: Removed duplicated region for block: B:21:0x009e  */
/* Code decompiled incorrectly, please refer to instructions dump. */
public void o0(android.widget.EditText r12, android.widget.TextView r13) {
    /*
    // Method dump skipped, instructions count: 202
    */
    throw new UnsupportedOperationException("Method not decompiled: com.ima.perfectlynormalapp.FirstFragment.o0(android.widget.EditText, android.widget.TextView):void");
}
```

It seems like `jadx` failed to decompile a huge chunk of code. But fret not! We can easily overcome this by passing jadx the `--show-bad-code` argument when running it to force it to decompile.

And we get this:

```java
public void o0(EditText editText, TextView textView) {
    String str;
    String obj = editText.getText().toString();
    boolean z = true;
    int length = obj.length() - 1;
    if (obj.length() >= 8) {
        if (obj.substring(0, 7).compareTo("WH2021{") == 0 && obj.substring(length).compareTo("}") == 0) {
            String[] strArr = {"VGhpc0lzTm90VGhlRmxhZw==", "U01VV2hpdGVIYXRDaGFsbGVuZ2U=", "gjhU9MzCkbTNF54MXwReLkE=", "yeLGMCaRA8p8xA==", "azMtkQ//3JA=", "zMq9wKxBrbpj1PQ9WLADXJaGRq1gnwyWdUj+2A=="};
            byte[] bArr = {-118, 107, 97, 123, 26, 43, -111, -20};
            try {
                byte[] decode = Base64.decode(obj.substring(7, length), 0);
                byte[] copyOf = Arrays.copyOf(decode, decode.length);
                for (int i = 0; i < decode.length; i++) {
                    copyOf[(decode.length - 1) - i] = (byte) (decode[i] ^ bArr[i % 8]);
                }
                if (Base64.encodeToString(copyOf, 0).trim().compareTo(strArr[2]) == 0) {
                    Log.d("RESULT", "True");
                    if (z) {
                        textView.setVisibility(4);
                        NavHostFragment.o0(this).c(R.id.action_FirstFragment_to_SecondFragment);
                        return;
                    }
                } else {
                    str = "False";
                    Log.d("RESULT", str);
                    z = false;
                    if (z) {
                    }
                }
            } catch (Exception e) {
                StringBuilder f = b.a.a.a.a.f("False, ");
                f.append(e.toString());
                str = f.toString();
            }
        } else {
            textView.setVisibility(0);
            textView.setText(R.string.ctf);
            return;
        }
    }
    textView.setVisibility(0);
    textView.setText(MainActivity.stringFromJNI());
}
```

As the description stated, this is a pretty easy cipher method, let's break it down:

1. We can deduce that `obj` contains the input from the user from `String obj = editText.getText().toString();`

2. We then see that `obj` must be of length >= 8 from ` if (obj.length() >= 8) {`

3. The first 8 characters of `obj` must be = to `WH2021{`, and the last character must be `}`. 

   ```java
    if (obj.substring(0, 7).compareTo("WH2021{") == 0 && obj.substring(length).compareTo("}") == 0)
   ```

   Hence, our input is probably the flag, and this method checks it. 

4. The contents in-between `{ }` are extracted and **base64-decoded**

   ```java
   byte[] decode = Base64.decode(obj.substring(7, length), 0);
   ```

   Hence, our **input flag is probably a base64-encoded string**.

5. A **copy** of the byte array is then made:

   ```java
   byte[] copyOf = Arrays.copyOf(decode, decode.length);
   ```

6. It then does some kind of **encoding to our input flag**

   ```java
   for (int i = 0; i < decode.length; i++) {
   	copyOf[(decode.length - 1) - i] = (byte) (decode[i] ^ bArr[i % 8]);
   }
   ```

   This seems to be:

   - Starting from the **back of `copyOf`**, encode each byte with the **xored result** of the byte from `bArr` and a **byte** from the **`decode`, starting from the front**

7. Next, it **encodes the byte array to base64** and compares it with `strArr[2]`= `gjhU9MzCkbTNF54MXwReLkE=`

   ```java
   if (Base64.encodeToString(copyOf, 0).trim().compareTo(strArr[2]) == 0)
   ```



## Decoding the Flag

At this stage, what we simply have to do is to reverse the process it took to get `gjhU9MzCkbTNF54MXwReLkE=`, and get the original input, which is the flag.

We can write a simple python script to do the trick:

```python
import base64

bArr = [-118, 107, 97, 123, 26, 43, -111, -20]
decode = base64.b64decode(b"gjhU9MzCkbTNF54MXwReLkE=")
flag = [0] * len(decode)
for x in range(0, len(decode), 1):
    testByte = decode[len(decode)-1-x] ^ bArr[x % 8]
    if (testByte < 0):
        testByte = testByte & int("ff", 16)
    flag[x] = testByte

finalFlag = b""
for x in flag:
    finalFlag += x.to_bytes(1, byteorder='big')
    
print(base64.b64encode(finalFlag).decode())
```

There are 2 things to take note of here:

1. `gjhU9MzCkbTNF54MXwReLkE=` decoded to bytes is technically "**reversed**" of the original input as we **xored it from the back onwards**. Hence we need to **xor it from the back** (with `bArr`) to get back the original string using:

   ```java
   decode[len(decode)-1-x] ^ bArr[x % 8]
   ```

2. Java only has **signed bytes** (-128 to 127). You will notice that some bytes do not fit this range. Hence you simply have to `&` it  by `0xFF` to convert it to signed bytes



Running the script, we get the flag:

```
WH2021{y0U/f0UnD/tH3/C51t/F1Ag=}
```



## Learning Points

- Analysing and reversing a simple cipher in an `apk`

------

# perfectlynormalapp (B) - 500 points (0 solves)

Now onwards to the 2nd flag of the application!



## Analysing the Java Function

Let's look at `SecondFragment`. Scrolling down, we see an interesting method:

```java
public void o0(EditText editText, TextView textView, TextView textView2) {
        String checkSF;
        int i = this.V + 1;
        this.V = i;
        textView2.setText(this.U[i % 3]);
        String obj = editText.getText().toString(); //obj = inputString
        int length = obj.length() - 1;
        if (obj.length() < 8) {
            textView.setVisibility(0);
            checkSF = MainActivity.stringFromJNI();
        } else if (obj.substring(0, 7).compareTo("WH2021{") == 0 && obj.substring(length).compareTo("}") == 0) { //Checks for flag format
            new MainActivity();
            String substring = obj.substring(0, 3); //WH2
            char charAt = substring.charAt(0);
            char charAt2 = substring.charAt(1);
            char charAt3 = substring.charAt(2);
            b.c.a.a aVar = MainActivity.p;
            Context context = MainActivity.o;
            Objects.requireNonNull(aVar);
            MainActivity.r = aVar.b(context, "SELECT * FROM keys WHERE id=" + (charAt % '+'));
            b.c.a.a aVar2 = MainActivity.p;
            Context context2 = MainActivity.o;
            Objects.requireNonNull(aVar2);
            MainActivity.q = aVar2.b(context2, "SELECT * FROM keys WHERE id=" + (charAt2 % 27));
            b.c.a.a aVar3 = MainActivity.p;
            Context context3 = MainActivity.o;
            Objects.requireNonNull(aVar3);
            MainActivity.s = aVar3.b(context3, "SELECT * FROM cipher WHERE id=" + (charAt3 % '#'));
            textView.setVisibility(0);
            checkSF = MainActivity.checkSF(obj.substring(7, length), MainActivity.r, MainActivity.q, MainActivity.s);
        } else {
            textView.setVisibility(0);
            textView.setText(R.string.ctf);
            return;
        }
        textView.setText(checkSF);
    }
```

We can again quickly deduce that `obj` is equivalent to our input string from `String obj = editText.getText().toString();`

It again checks for the flag format here: 

Looking down, we see that a `checkSF = MainActivity.stringFromJNI();`. A quick `Find Usage` reveals that this is a **native function**, which we will look at later

The next lines of code can be summarised as follows:

1. ```java
   String substring = obj.substring(0, 3); //Equivalent to "WH2"
   ```

2. ```java
   char charAt = substring.charAt(0); // W
   char charAt2 = substring.charAt(1); // H
   char charAt3 = substring.charAt(2); // 2
   ```

3. ```java
   MainActivity.r = aVar.b(context, "SELECT * FROM keys WHERE id=" + (charAt % '+'));
   ```

   - Looking at the `b` function, it seems to simply run this **SQL statement**. Looking around, we can see that it is accessing `Nope.db` to run these statements

     ```java
     InputStream open = this.c.getAssets().open("Nope.db");
     FileOutputStream fileOutputStream = new FileOutputStream(e);
     byte[] bArr = new byte[1024];
     ```

   - The ASCII value of `charAt` is `W=87` and `+=43`. Hence, `87 % 43` is `1`

   - Looking at `Nope.db`'s `keys` table, we can get the value: 

     ```
     MainActivity.r = 44f2077a3dc2ee83ba02bb373c3364b0
     ```

4. Repeating this process for the next 2 `SQL` statements, we will get the values:

   ```
   MainActivity.q = 96038d47100e7e5c7ab07e8fa398d05e
   MainActivity.s = SqExeby3LwI16tZHvi8kXHIh6f3XuAVaf17P7w4i4+E=
   ```

5. Finally, it calls the **native function** `checkSF` with:

   ```java
   checkSF = MainActivity.checkSF(obj.substring(7, length), MainActivity.r, MainActivity.q, MainActivity.s);
   ```



## Analysing the Native Function

Let's head over to `IDA` to see what the native function is doing!

The `stringFromJNI` function doesn't tell us much unfortunately. But looking around, we find a function with the **correct number of arguments**, and also has an **interesting name:** `checkSF`

```c
__int64 __fastcall Java_com_ima_perfectlynormalapp_MainActivity_checkSF(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  const char *v11; // r15
  const char *v12; // rbp
  const char *v13; // r13
  const char *v14; // r12
  char *v15; // rsi
  __int64 v16; // rbx
  __int128 v18; // [rsp+0h] [rbp-58h] BYREF
  void *ptr; // [rsp+10h] [rbp-48h]
  unsigned __int64 v20; // [rsp+20h] [rbp-38h]

  v20 = __readfsqword(0x28u);
  v11 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
  v12 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a4, 0LL);
  v13 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a5, 0LL);
  v14 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a6, 0LL);
  v18 = 0LL;
  ptr = 0LL;
  if ( (unsigned __int8)verifySflag(v11, v12, v13, v14) )
    std::string::assign(&v18, "Congratulations, you have found the correct flag!", 49LL);
  else
    std::string::assign(&v18, "Sorry, that was the wrong flag. Try again", 41LL);
  (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v11);
  (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v12);
  (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v13);
  (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v14);
  if ( (v18 & 1) != 0 )
    v15 = (char *)ptr;
  else
    v15 = (char *)&v18 + 1;
  v16 = (*(__int64 (__fastcall **)(__int64, char *))(*(_QWORD *)a1 + 1336LL))(a1, v15);
  if ( (v18 & 1) != 0 )
    operator delete(ptr);
  return v16;
}
```

<u>**Note:**</u> In general, the first 2 arguments `a1` and `a2` for `apk` native functions are defined by the system or something, so our actual arguments are `a3`, `a4`, `a5`, and `a6` (exactly 4 arguments which we passed in)

We can see that `a3`...`a6` are passed into some kind of function we can't determine, and then assigned to `v11`...`v14`. `verifySflag()` is then called with our 4 arguments.



At this point, our arguments are:

```
WH2021{(.*)} //a1 (whatever's inside the match group)
44f2077a3dc2ee83ba02bb373c3364b0 //a2
96038d47100e7e5c7ab07e8fa398d05e //a3
SqExeby3LwI16tZHvi8kXHIh6f3XuAVaf17P7w4i4+E= //a4
```

We are then greeted with a pretty long function, with some nice references to `AES` and more

```c
__int64 __fastcall verifySflag(const char *a1, const char *a2, const char *a3, const char *a4)
{
  size_t v5; // rax
  int v6; // er12
  unsigned __int8 *v7; // rbx
  unsigned __int64 i; // r15
  int v9; // er12
  unsigned __int8 *v10; // rbp
  unsigned __int64 j; // rbx
  size_t lengthOfCipher; // r14
  void *input_enc; // r15
  void *encryptedOutput; // r12
  unsigned __int64 v15; // rbx
  unsigned __int8 *v16; // rbp
  const char *v17; // rax
  char *v18; // rbp
  char nptr[2]; // [rsp+2h] [rbp-66h] BYREF
  int c; // [rsp+4h] [rbp-64h]
  void *src; // [rsp+8h] [rbp-60h]
  size_t v23; // [rsp+10h] [rbp-58h]
  char *s2; // [rsp+18h] [rbp-50h]
  unsigned __int8 v25[16]; // [rsp+20h] [rbp-48h] BYREF
  unsigned __int64 v26; // [rsp+30h] [rbp-38h]

  s2 = (char *)a4;
  v26 = __readfsqword(0x28u);
  src = (void *)a1;
  v5 = strlen(a1);
  v6 = (v5 + ((unsigned int)((int)v5 >> 31) >> 28)) & 0xFFFFFFF0;
  v23 = v5;
  c = (int)v5 % 16;
  aes_key = malloc(0xF4uLL);
  *(_QWORD *)aes_key = 0LL;
  v7 = v25;
  for ( i = 0LL; i < 0x20; i += 2LL )
  {
    *(_WORD *)nptr = *(_WORD *)&a3[i];
    *v7++ = strtol(nptr, 0LL, 16);              // converts nptr, a string into integer (from hex)
  }
  v9 = v6 + 16;
  c = 16 - c;
  v10 = v25;
  private_AES_set_encrypt_key(v25, 128LL, aes_key);// userKey, length in bits(16 bytes), aes_key is a struct formed from userKey 
  for ( j = 0LL; j < 0x20; j += 2LL )
  {
    *(_WORD *)nptr = *(_WORD *)&a2[j];
    *v10++ = strtol(nptr, 0LL, 16);
  }
  lengthOfCipher = v9;
  input_enc = malloc(v9);
  encryptedOutput = malloc(v9);
  memset(input_enc, c, lengthOfCipher);
  memcpy(input_enc, src, (int)v23);             // src copied into v13
  v15 = 0LL;
  memset(encryptedOutput, 0, lengthOfCipher);
  v16 = v25;
  src = input_enc;
  AES_cbc_encrypt((__int64)input_enc, (__int64)encryptedOutput, lengthOfCipher, (__int64)aes_key, (__int64)v25, 1LL); // v25 is IV
  do
  {
    *(_WORD *)nptr = *(_WORD *)&a2[v15];
    *v16 = strtol(nptr, 0LL, 16);
    v15 += 2LL;
    ++v16;
  }
  while ( v15 < 32 );
  v17 = (const char *)b64_encode((const unsigned __int8 *)encryptedOutput, lengthOfCipher);
  __android_log_print(4LL, "GENERICJNI", "Encrypted: %s", v17);
  v18 = (char *)ivcipher_b64_encode((unsigned __int8 *)encryptedOutput, v25, lengthOfCipher);// v25 in this case = IV
  __android_log_print(4LL, "GENERICJNI", "Result: %s", v18);
  free(src);
  free(encryptedOutput);
  free(aes_key);
  LOBYTE(v15) = strcmp(v18, s2) == 0;           // if strings are equal, return 0 == 0, return true
  free(v18);
  return (unsigned int)v15;
}
```

I won't be going through every detail of this code as it is pretty long (and I have annotated quite a bit) but here is a summary:

1. ```c
   v7 = v25;
     for ( i = 0LL; i < 0x20; i += 2LL )
     {
       *(_WORD *)nptr = *(_WORD *)&a3[i];
       *v7++ = strtol(nptr, 0LL, 16); // converts nptr, a string into integer (from hex)
     }
     v9 = v6 + 16;
     c = 16 - c;
     v10 = v25;
     private_AES_set_encrypt_key(v25, 128LL, aes_key); // userKey, length in bits(16 bytes), aes_key is a struct formed from userKey 
   ```

   - This code **hex-decodes** the contents of `a3` and saves it to `v7`, which is in turn referencing `v25`
   - `v25` is used to create an `aes_key` struct which presumably will be used for **encoding** later on

2. ```c
   src = (void *)a1;
   ...
   memcpy(input_enc, src, (int)v23);             // src copied into v13
   v15 = 0LL;
   memset(encryptedOutput, 0, lengthOfCipher);
   v16 = v25;
   src = input_enc;
   AES_cbc_encrypt((__int64)input_enc, (__int64)encryptedOutput, lengthOfCipher, (__int64)aes_key, (__int64)v25, 1LL); // v25 is IV
   ```

   - This code first copies `src`, which is equivalent to `a1`, which is the contents between the flag format `WH2021{.*}`
   - Looking at the docs for sometime, I figured out what each argument meant for `ABS_cbc_encrypt`
   - Hence, this function encrypts out input from `input_enc` using a `key` and an `IV`, and outputs it to `encryptedOutput`

3. ```c
   v18 = (char *)ivcipher_b64_encode((unsigned __int8 *)encryptedOutput, v25, lengthOfCipher); // v25 in this case = IV
   __android_log_print(4LL, "GENERICJNI", "Result: %s", v18);
   free(src);
   free(encryptedOutput);
   free(aes_key);
   LOBYTE(v15) = strcmp(v18, s2) == 0; // if strings are equal, return 0 == 0, return true
   ```

   - This code calls `ivcipher_b64_encode`, which basically **returns `IV+encryptedOutput`** and **base64-encodes it**
   - We then see that `v18` is compared to `s2`, which is equivalent to `a4` = `SqExeby3LwI16tZHvi8kXHIh6f3XuAVaf17P7w4i4+E=`

Hence we can now deduce what each of the arguments mean:

```
WH2021{(.*)} //a1 in the match group
44f2077a3dc2ee83ba02bb373c3364b0 //a2 - IV (hex-encoded)
96038d47100e7e5c7ab07e8fa398d05e //a3 - key (hex-encoded)
SqExeby3LwI16tZHvi8kXHIh6f3XuAVaf17P7w4i4+E= //a4 - IV+ciphertext (b64-encoded)
```

We can then write a simple python script to **decrypt the ciphertext** using these details (since `AES` is a symmetric cipher)

```python
from Crypto.Cipher import AES
import base64

key = bytearray.fromhex("96038d47100e7e5c7ab07e8fa398d05e")
IV = bytearray.fromhex("44f2077a3dc2ee83ba02bb373c3364b0")
contents = base64.b64decode(b"RPIHej3C7oO6Ars3PDNksPRj2fEbEEsdmf70LUd/Svm3RrophVXGYDB7LL4Pb+QL")[16:] #this string is IV+Cipher, IV is 16 bytes

cipher = AES.new(key, AES.MODE_CBC, IV)

print(cipher.decrypt(contents).decode())
```

And we get:

```
Y0uRe/A/w1ZaRd/H4rRy
```

Hence the flag is:

```
WH2021{Y0uRe/A/w1ZaRd/H4rRy}
```



## Learning Points

- Analysing native functions (specifically the `OpenSSL` library) when being used in `C`
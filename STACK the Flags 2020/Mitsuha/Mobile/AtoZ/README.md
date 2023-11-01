# A to Z of COViD! [1986]
5 SOLVES

Over here, members learn all about COViD, and COViD wants to enlighten everyone about the organisation. Go on, read them all!
# Finding flag
In `AtoZCovid.java`:
```java
case 42:
    new BottomSheetDialogEdit("Put the flag here").e(getSupportFragmentManager(), "ModalBtmSheetEdit");
    return;
```
In `BottomSheetDialogEdit.java`, there are these lines:
```java
public native int secretFunction2(String str, int i);
...
int flagStatus = BottomSheetDialogEdit.this.secretFunction2(enteredFlagString, enteredFlagString.length());
```
`secretFunction2()` looks like this (prettified):
```c
int secretFunction2(char *a3, int a4) {
  __int128 v10[16]; // [rsp+0h] [rbp-138h] BYREF

  if ( a4 <= 0 ) return 1LL;
  char *v8 = (char *)malloc(a4);
  xmmword_44200 = xmmword_354C0;
  xmmword_44210 = xmmword_354D0;
  memset(v10, 0, 16*sizeof(__int128));
  aes_key_setup(&xmmword_44200, v10, 256LL);
  int v5 = 0;
  do {
    aes_encrypt(v5 + a3, &v8[v5], v10, 256LL);
    v5 += 16;
  } while (v5 < a4);
  if (!memcmp(v8, &unk_44030, a4))
    return 0;
  else
    return (unsigned int)(memcmp(v8, &unk_44050, a4) == 0) + 1;
}
```
This function encrypts the input with an AES key (using ECB) embedded at `xmmword_354(C|D)0`, and compares it with encrypted bytes `unk_44030`. Because AES is symmetrical, a short python script will solve for the encryption here:
```python
from Crypto.Cipher import AES
# dump these values out with IDA-python.
key = (0x869DCFC6C23F21ADC280C2BDA4A337B7C536F9069D5F5C8B6F5D8465D400D12C).to_bytes(256//8,'little')
ciphertext = (0x2ee5ce8273a9addcdb1bee214cce96126a52f04b534f34ecfaba62a6a54e882c).to_bytes(256//8,'big')
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(ciphertext))
```
Result: `govtech-csg{I_kN0w_Wh4t_t0_d0!!}`
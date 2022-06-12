# NUS Grey Cat The Flag: 🩸 Memory Game (Part 2)
*RE, 500 -> 423 points*

> Can you finish MASTER difficulty in 20 seconds? If you can, the flag will be given to you through logcat with the tag `FLAG`.  
> - daniellimws

## Analysis
*This challenge is a continuation from Memory Game (Part 1), recommended to check out Part 1 first.*

Previously we have noted in part 1, the flag was only in the application assets and we have yet to divulge into the codebase with the actual game logic.

As usual, we will first try a static APK analysis to figure out the flag without actually running the game.

For the tools we will be using [jadx](https://github.com/skylot/jadx) (to decompile apk to java source code).

```bash
$ jadx --show-bad-code memory-game.apk
```
(the `--show-bad-code` flag is needed to display the broken functions)

Firing up jadx to decompile the APK, we see that there is some code generated under the package `com.snatik.matches`.

Probing around revealed that the core game logic and flag was in the `com/snatik/matches/engine/Engine.java` file, under the `onEvent` function.

```java
/* JADX WARN: Removed duplicated region for block: B:32:0x00ea A[LOOP:0: B:30:0x00e6->B:32:0x00ea, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x011b A[LOOP:1: B:39:0x0119->B:40:0x011b, LOOP_END] */
    @Override // com.snatik.matches.events.EventObserverAdapter, com.snatik.matches.events.EventObserver
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    public void onEvent(FlipCardEvent flipCardEvent) {
        Cipher cipher;
        SecretKeyFactory secretKeyFactory;
        byte[] bArr;
        int i;
        byte[] bArr2;
        int i2;
```

We realised that the function was broken as it was not decompiled cleanly (if you did not decompile with `--show-bad-code` it would just say "function not decompiled")

## More Analysis
Taking a closer look at that particular function, we see that there is a bunch of try/catches in attempts to create confusion:

```java
SecretKeySpec secretKeySpec = null;
  try {
      secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      try {
          cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      } catch (NoSuchAlgorithmException e2) {
          e = e2;
          e.printStackTrace();
          cipher = null;
          Rnd.reSeed();
          bArr = new byte[16];
          while (i < 16) {
          }
          secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(new PBEKeySpec(BuildConfig.VERSION_NAME.toCharArray(), bArr, 65536, 256)).getEncoded(), "AES");
          bArr2 = new byte[16];
          while (i2 < 16) {
          }
          cipher.init(2, secretKeySpec, new IvParameterSpec(bArr2));
          Log.i("FLAG", new String(cipher.doFinal(Base64.decode("diDrBf4+uZMtDV+0k/3BCGM4xyTpEyGEuUFYegIaSjQyQcgfIfZRbvGQ9hHMqnuflNCKv4HW/NXq93j4QqLc/Q==", 0)), StandardCharsets.UTF_8));
          this.mFlippedId = -1;
      } catch (NoSuchPaddingException e3) {
          e = e3;
          e.printStackTrace();
          cipher = null;
          Rnd.reSeed();
          bArr = new byte[16];
          while (i < 16) {
          }
          secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(new PBEKeySpec(BuildConfig.VERSION_NAME.toCharArray(), bArr, 65536, 256)).getEncoded(), "AES");
          bArr2 = new byte[16];
          while (i2 < 16) {
          }
          cipher.init(2, secretKeySpec, new IvParameterSpec(bArr2));
          Log.i("FLAG", new String(cipher.doFinal(Base64.decode("diDrBf4+uZMtDV+0k/3BCGM4xyTpEyGEuUFYegIaSjQyQcgfIfZRbvGQ9hHMqnuflNCKv4HW/NXq93j4QqLc/Q==", 0)), StandardCharsets.UTF_8));
          this.mFlippedId = -1;
      }
  } catch (NoSuchAlgorithmException | NoSuchPaddingException e4) {
      e = e4;
      secretKeyFactory = null;
  }
  Rnd.reSeed();
  bArr = new byte[16];
  for (i = 0; i < 16; i++) {
      bArr[i] = (byte) Rnd.get(256);
  }
  try {
      secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(new PBEKeySpec(BuildConfig.VERSION_NAME.toCharArray(), bArr, 65536, 256)).getEncoded(), "AES");
  } catch (InvalidKeySpecException e5) {
      e5.printStackTrace();
  }
  bArr2 = new byte[16];
  for (i2 = 0; i2 < 16; i2++) {
      bArr2[i2] = (byte) Rnd.get(256);
  }
  try {
      cipher.init(2, secretKeySpec, new IvParameterSpec(bArr2));
  } catch (InvalidAlgorithmParameterException e6) {
      e6.printStackTrace();
  } catch (InvalidKeyException e7) {
      e7.printStackTrace();
  }
  try {
      Log.i("FLAG", new String(cipher.doFinal(Base64.decode("diDrBf4+uZMtDV+0k/3BCGM4xyTpEyGEuUFYegIaSjQyQcgfIfZRbvGQ9hHMqnuflNCKv4HW/NXq93j4QqLc/Q==", 0)), StandardCharsets.UTF_8));
  } catch (BadPaddingException e8) {
      e8.printStackTrace();
  } catch (IllegalBlockSizeException e9) {
      e9.printStackTrace();
  }
}
```

There seems to be also a few repeated lines of code that tries to decode a Base64 string to obtain the flag.

Upon closer inspection, the decoded base64 goes into a cipher function that seemingly decrypts the flag.

So to get any further, we need to figure out how cipher works exactly. But before that, we need to know which code runs and what doesn't.

## Solution
Trying out some of the statements in a local environment, we get:

```java
public class Main {
  public static void main(String args[]) {
    SecretKeyFactor secretKeyFactory;
    SecretKeySpec secretKeySpec = null;
    Cipher cipher;
    try {
        secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException e2) {
            e = e2;
            e.printStackTrace();
        } catch (NoSuchPaddingException e3) {
            e = e3;
            e.printStackTrace();
        }
    } catch (NoSuchAlgorithmException |   NoSuchPaddingException e4) {
        e = e4;
        secretKeyFactory = null;
    }
  }
}
```
There were no runtime or build errors, that tells us that the catch statements were not called upon.

Moving on, we continune to look down and analyse the code.

```java
Rnd.reSeed();
bArr = new byte[16];
for (i = 0; i < 16; i++) {
    bArr[i] = (byte) Rnd.get(256);
}
try {
    secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(new PBEKeySpec(BuildConfig.VERSION_NAME.toCharArray(), bArr, 65536, 256)).getEncoded(), "AES");
} catch (InvalidKeySpecException e5) {
    e5.printStackTrace();
}
bArr2 = new byte[16];
for (i2 = 0; i2 < 16; i2++) {
    bArr2[i2] = (byte) Rnd.get(256);
}
try {
    cipher.init(2, secretKeySpec, new IvParameterSpec(bArr2));
} catch (InvalidAlgorithmParameterException e6) {
    e6.printStackTrace();
} catch (InvalidKeyException e7) {
    e7.printStackTrace();
}
try {
    Log.i("FLAG", new String(cipher.doFinal(Base64.decode("diDrBf4+uZMtDV+0k/3BCGM4xyTpEyGEuUFYegIaSjQyQcgfIfZRbvGQ9hHMqnuflNCKv4HW/NXq93j4QqLc/Q==", 0)), StandardCharsets.UTF_8));
} catch (BadPaddingException e8) {
    e8.printStackTrace();
} catch (IllegalBlockSizeException e9) {
    e9.printStackTrace();
}
```

Hmm. This looks much more interesting and could possibly lead to the flag.

There also appears to be a custom `Rnd` function used that would be part of the flag process

There is no better option than to just copy and paste the decompiled source files as-is (but remove/edit the package name first). The necessary files are `Rnd.java` and `MTRandom.java` (required by `Rnd.java`).

All we need to do now is to emulate the functionality of the above code, so that it generates and prints out the flag for us.

This is mainly trial and error to fix the various imports and code structure.

### Full solution script (`Main.java`)
```java
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Base64;

public class Main {
  public static final String VERSION_NAME = "1.01.001007";
  public static void main(String args[]) throws NoSuchAlgorithmException,NoSuchPaddingException {
    Cipher cipher;
    SecretKeyFactory secretKeyFactory;
    byte[] bArr;
    int i;
    byte[] bArr2;
    int i2;
    GeneralSecurityException e;
    SecretKeySpec secretKeySpec = null;

    secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

    Rnd.reSeed();
    bArr = new byte[16];
    for (i = 0; i < 16; i++) {
        bArr[i] = (byte) Rnd.get(256);
    }
    try {
        secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(new PBEKeySpec(VERSION_NAME.toCharArray(), bArr, 65536, 256)).getEncoded(), "AES");
    } catch (InvalidKeySpecException e5) {
        e5.printStackTrace();
    }
    bArr2 = new byte[16];
    for (i2 = 0; i2 < 16; i2++) {
        bArr2[i2] = (byte) Rnd.get(256);
    }
    try {
        cipher.init(2, secretKeySpec, new IvParameterSpec(bArr2));
    } catch (InvalidAlgorithmParameterException e6) {
        e6.printStackTrace();
    } catch (InvalidKeyException e7) {
        e7.printStackTrace();
    }
    try {
        System.out.println(new String(cipher.doFinal(Base64.getDecoder().decode("diDrBf4+uZMtDV+0k/3BCGM4xyTpEyGEuUFYegIaSjQyQcgfIfZRbvGQ9hHMqnuflNCKv4HW/NXq93j4QqLc/Q==")), StandardCharsets.UTF_8));
    } catch (BadPaddingException e8) {
        e8.printStackTrace();
    } catch (IllegalBlockSizeException e9) {
        e9.printStackTrace();
    }
  }
}
```

It did use the `BuildConfig.VERSION` static variable as well, which can be found in the `com/snatik/matches/BuildConfig.java` file.

Do also take note to replace all the Android-specific functions such as `Base64` and `Log` with their native Java counterparts (`android.util.Base64 -> java.util.Base64` and `Log.i() -> System.out.println()`)

Now we just need to compile and run our code to "generate" the flag for us!

```bash
$ javac Main.java MTRandom.java Rnd.java
$ java Main
grey{hum4n_m3m0ry_i5_4lw4y5_b3tt3r_th4n_r4nd0m_4cc3ss_m3m0ry}
```

Voila! We have successfully obtained the flag!!

**Flag:** ```grey{hum4n_m3m0ry_i5_4lw4y5_b3tt3r_th4n_r4nd0m_4cc3ss_m3m0ry}```

## Notes/Takeaways
- Static analysis should always be the first consideration due to its speed (not necessary to run/debug app), and to get a feel of the whole program itself, see how it works, then moving on to dynamic analysis if required. (managed to FB 🩸 with only a static analysis)
- Fortunately there was no more continuation parts that required APK patching/dynamic analysis necessary for the challenge and involving more advanced tools (e.g. APKTool/Frida) (I know the hint provided was to use [Frida](https://frida.re/) instead)
- The only difficult part is mainly reading and understanding how the Java logic flow works, so to weed out deadcode (the tons of empty while statements) and inaccessible code (such as the try/catch) to know what you should be actually looking out for
- Pretty sure there are multiple ways to solve this challenge (e.g. dynamic analysis/injection or patching) but due to time constraints for writeups there was no PoC made

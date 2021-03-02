# Login
```
It's time for a simple, relaxing challenge.
Can you find the correct credentials?
```

This was my first foray into Mobile RE. It was rather painful but at least I learnt more about dissecting Android applications.

## Reconnaissance

We are presented with an APK file which reveals some interesting code:
![](Images\ddea.png)
![](Images\m_userid.png)
![](Images\m_password.png)
![](Images\checks.png)
![](Images\javapassword.png)
![](Images\aestool.png)
All from LoginDataSource.java and AESTools.java. The rest were... junk, to say the least.


## Making Sense of Everything.
We seem to need to recover 3 things:
- The `user ID`
- The first 4 characters of the `password`
- The last 8 characters of the `password`.

The first two are relatively trivial.
![](Images\userid.png)
![](Images\first4.png)

The only troublesome one was the `getNativePassword()` function.

However, upon following, we noticed that there was this `ddea.so` file (4 different binaries, we selected the ARM 64-bit one). Opening it gives us:
![](Images\getnativepassword.png)
which... OK, it is what we want but...
It is pretty intimidating.

That is... if you **don't** look at the program graph.
![](Images\xor.png)

It is evident that each and every byte is being xorred, from `byte_8F0` and `byte_901` to `byte_8FF` and `byte_910`.
This will give us the key.
(Sorry ;^; the screen was way too long)

So let us see if we can xor them together...
![](Images\recoverkey.png)

Bingo.
Thus we decrypt the AES ciphertext as:

![](Images\decrypt.png)

Thus we submit
```
Username: User1337
Password: L1v3p2Zzw0rD
```

And receive the flag: `DSO-NUS{71bcade1b51d529ad5c9d23657662901a4be6eb7296c76fecee1e892a2d8af3e}`
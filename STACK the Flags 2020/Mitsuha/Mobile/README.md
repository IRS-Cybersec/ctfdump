# Generalised approach
At the start of the CTF, we slapped `mobile-challenge.apk` into jadex for static analysis. Our solution for nearly every challenge boils down to this:

1. Locate the relevant part of the decompiled Java output that corresponds with the challenge of interest.
2. Analyse it for what needs to be done. Where possible (e.g. `Welcome to Korovax Mobile`), figure out the interactive solution for the challenge from the Java code. The challenges presented two roadblocks to this method:
   * Many challenges involved calls to native-lib functions. I used IDA Pro to reverse my way through these.
   * For one particular challenge, `All about Korovax!`, I was unable to determine the interactive method to solve the challenge. In this case, I solve the challenge by directly obtaining the flag from the program, rather than concentrating on the intended path.

Some of the beginner challenges were also obtained by just applying `strings/grep`. No write-ups are planned for those challenges.

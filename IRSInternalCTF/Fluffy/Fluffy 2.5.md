# Prerequisites

An easy way to do this is Metasploit. Create a session as instructed from Fluffy III.md

Some of you solved this challenge by using web request tools like php's curl, or windows curl, but the concept behind this is **pivoting**.

The end goal is to be able to use this machine as a staging point to launch attacks against other machines. i.e. attack with the compromised machine.

This challenge has many methods to solve. However, this tutorial will use Metasploit's portfwd command. Low privileges are sufficient.

# Port Forwarding

The concept is to forward our connections from an accessible port to 172.104.33.55:7200, the target port.

If we do ``nc 172.104.33.55 7200`` normally, we get this output:

```
Hi there, <your ip>. You must connect from 172.104.49.68 (Fluffyyy) to access the vault.
```

So the task is simple (not necessarily easy ;>). We must connect to 172.104.33.55:7200 with our compromised Windows machine.

# Actually Port Forwarding: Meterpreter

Once we have a meterpreter session up, let's use the portfwd command

``meterpreter
meterpreter> portfwd add -l 9999 -p 7200 -r 172.104.33.55
``

What does this command mean?
``-l``  refers to our attacking machine's port 9999
``-p``  refers to the remote port 7200 on 172.104.33.55
``-r``  refers to the remote host we want to connect to (this case, 172.104.33.55)

Together, it means that if we connect to localhost:9999, it will be connecting to 172.104.33.55:7200 via the compromised machine. 

So now, all we must do, is

```bash
nc localhost 9999
```

![alt text](https://imgur.com/j6XfQR9.png)

Win.

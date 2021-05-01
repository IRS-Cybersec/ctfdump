# General Task

So we are told that there's a website on 172.104.49.68. Websites are normally hosted on port 80, but visiting http://172.104.49.68 didn't work, so that means it isn't there for this machine.

Let's bring out our port scanning tools.

# NMap

```bash
nmap -sS -T5 -v 172.104.49.68
```

Output:
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 06:10 UTC
Initiating Ping Scan at 06:10
Scanning 172.104.49.68 [4 ports]
Completed Ping Scan at 06:10, 1.51s elapsed (1 total hosts)
Nmap scan report for 172.104.49.68 [host down]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 1.56 seconds
           Raw packets sent: 8 (304B) | Rcvd: 0 (0B)
```
Some fellas contacted me regarding this. But it's not a big deal. In fact, the solution is even stated right in that error. Windows blocks ping probes. Trying ``ping`` will also fail.

So the right command is:

```bash
nmap -sS -T5 -v 172.104.49.68 -Pn
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 06:10 UTC
Initiating Parallel DNS resolution of 1 host. at 06:10
Completed Parallel DNS resolution of 1 host. at 06:10, 0.19s elapsed
Initiating SYN Stealth Scan at 06:10
Scanning li1629-68.members.linode.com (172.104.49.68) [1000 ports]
Discovered open port 3389/tcp on 172.104.49.68
Discovered open port 1001/tcp on 172.104.49.68
Discovered open port 1000/tcp on 172.104.49.68
Completed SYN Stealth Scan at 06:10, 3.02s elapsed (1000 total ports)
Nmap scan report for li1629-68.members.linode.com (172.104.49.68)
Host is up (0.00064s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
1000/tcp open  cadlock
1001/tcp open  webpush
3389/tcp open  ms-wbt-server

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.26 seconds
           Raw packets sent: 1998 (87.912KB) | Rcvd: 4 (176B)
root@localhost:~# ping 172.104.49.68
PING 172.104.49.68 (172.104.49.68) 56(84) bytes of data.
^C
--- 172.104.49.68 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4075ms
```

There. Now we have 3 ports to work with. But Leonard says 3389 is RDP, and not to touch it. So great for us. Only 2 ports to work with.
Let's check it on our browser

http://172.104.49.68:1000/

![alt text](https://imgur.com/FuuXhlM.png)

Ah. Clean and straightforward.

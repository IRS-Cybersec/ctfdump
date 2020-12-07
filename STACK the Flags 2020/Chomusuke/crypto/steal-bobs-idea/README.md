# Hold the line! Perimeter defences doing it's work!
**960 Points // 16 Solves**

Bob wants Alice to help him design the stream cipher's keystream generator base on his rough idea. Can COViD steal Bob's "protected" idea? 

## Getting the zip
We are given a `.pcap` file, which opens in [Wireshark](https://www.wireshark.org/). After opening, we use the oldest trick in the book and sort by size, and find the largest packets.

![Sorting by packet size](wireshark-sort.png)

We can now follow the TCP stream by pressing `Ctrl` + `Alt` + `Shift` + `T`, or simply by right clicking:

![Following the TCP stream](wireshark-follow.png)

The stream started with `PK`, which is part of the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) of a `.zip` file. Wireshark allows us to easily export the stream as a file by selecting "Raw" and clicking "Save as":

![Saving the TCP stream](wireshark-save.png)

Now, we have a valid, but password protected zip file.

## Decrypting the file
The password information is also stored in the pcap, under a different TCP stream. We opted to check for TCP streams because they usually contain important data.

* UDP: we checked through these as well
* ICMP: this is for `ping` requests and usually does not contain data
* DNS: this is for DNS lookups and would only include DNS data, but challenge setters _could_ include real information in this
* ARP: this is for networking and would not carry data
* SSDP: honestly I have no idea what this does

```
p = 298161833288328455288826827978944092433
g = 216590906870332474191827756801961881648
g^a = 181553548982634226931709548695881171814
g^b = 64889049934231151703132324484506000958
Hi Alice, could you please help me to design a keystream generator according to the file I share in the file server so that I can use it to encrypt my 500-bytes secret message? Please make sure it run with maximum period without repeating the keystream. The password to protect the file is our shared Diffie-Hellman key in digits. Thanks.
```
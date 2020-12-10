# The suspicious frequency monitoring alert!
*We received an alert from our smart city’s frequency monitoring and noticed some anomalies. Figure out what is happening!*

### Challenge observation
- We are given a .pcap file as part of the challenge, and opening the challenge we see that there are a bunch of WiFi packets inside.
- This likely means that we need to find some hidden transmission through WiFi within all these packets.
- Transmission will likely refer to the Beacon Frames sent by routers and Access Points (APs), so we filter the packets by the packet type (Beacon Frames)
- Scrolling to a random beacon frame packet, we find out that the type of packet is 8.
- Hence, Filter Command: `wlan.fc.subtype == 8`

### Large? No its too big
- Going by instinct, we roughly know that hidden information are usually inside either the largest or the smallest packets.
- After opening the capture in Wireshark, we sort the packets by the packet length with the largest first.
- Looking at the top few packets did not seem to reveal anything suspicious and seemed like normal broadcast packets.

### Small and suspicious
- So we move on to look at the smaller packets, and we see that the packet do look somewhat "normal" on the outside.
- However, upon taking a closer look, we see that there is some extra data at the end of the packet that does not seem to be visible in other beacon frames (compared to the ones above).
- This data is rather suspicious, so we extract them from the packets.

### Beep-Boop!
- Copying all the extra information from the packets, we end up with something as follow (in hex):
```
30100000343a 526d6c66535539554958303d
30100000333a 556b46556157394f58316470
30100000323a 633264375258686d61577830
30100000313a 5a3239326447566a6143316a
```
- Looking at the ASCII values of 0x31, 0x32, 0x33, 0x34, 0x3a we see that they are numerals from 1-4 and the character ':' respectively.
- This could represent the order of the transmission!
- We convert the hex values after the initial segment to a large string based off the order of the packets: `5a3239326447566a6143316a633264375258686d61577830556b46556157394f58316470526d6c66535539554958303d`
- Converting this hex string to an ASCII string, we get: `Z292dGVjaC1jc2d7RXhmaWx0UkFUaW9OX1dpRmlfSU9UIX0=`
- Then, converting the base-64 string to ASCII again, we finally obtain the flag.

### Flag
```govtech-csg{ExfiltRATioN_WiFi_IOT!}```

### Learning Outcomes
1. Even though we see sooooooo many packets (8000+), we should not be discouraged and instead look for hints in the challenge.
2. Knowing that the length of a packet will be a great way to find interesting packets for similar challenges like these!
3. Trial and Error is a great tool to help you find your way through this challenge, I went to try multiple different things such as hidden SSID names and weird SSID names but found that they were not the flag.

// TODO: add images
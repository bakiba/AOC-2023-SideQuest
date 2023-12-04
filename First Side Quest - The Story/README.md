 # First Side Quest - The Story
**First Side Quest Challenge Key**

This key is divided into four parts. Three will be posted on our social media channels between Tuesday, 28th November and Thursday, 30th November. The final part of the key will be posted in this room, on December 1st, 4 pm GMT. Find them all, put them together, and uncover the link to the first secret challenge! All the links to our social media channels can be found in Task 3 of the main Advent of Cyber room.
This key is divided into four parts. Three will be posted on our social media channels between Tuesday, 28th November and Thursday, 30th November. The final part of the key will be posted in this room, on December 1st, 4 pm GMT. Find them all, put them together, and uncover the link to the first secret challenge! All the links to our social media channels can be found in Task 3 of the main Advent of Cyber room.

## 4 QR codes
To obtain 4 codes, you need to find them on social media as mentioned in the Task 3 of the main Advent of Cyber room . 
![](img/20231202213947.png)

Here are locations where to find the 4 qr codes:
1. First QR code is right on the TryHackme side challenge page: https://assets.tryhackme.com/additional/aoc2023/6d156/50af2.png

    ![](img/20231202213152.png)

2. Second, was most difficult for me to find - as pinned message on TryHackme discord channel #aoc-2023-side-quest: https://assets.tryhackme.com/additional/aoc2023/b3620/e94fa.png

    ![](img/20231202213531.png)

3. Third is located on [Linkedin](https://www.linkedin.com/posts/tryhackme_can-you-help-elf-mcskidy-and-her-team-tackle-activity-7135598321280188416-5wnQ): https://assets.tryhackme.com/additional/aoc2023/5d60a/809cd.png

    ![](img/20231202214232.png)

4. Last QR code is located on [Twitter](https://twitter.com/RealTryHackMe/status/1730184898365767880): https://assets.tryhackme.com/additional/aoc2023/2f7f8/0f93a.png

    ![](img/20231202214823.png)

After uploading all 4 QR codes to the site under the Task 5 "View Site" button, you will get the link to secret room: https://tryhackme.com/room/adv3nt0fdbopsjcap

![](img/20231202215243.png)

## The Story

Here we learn that the Bandit Yeti obtained some Wi-Fi chit-chat capture from Van Spy character who infiltrated elf’s network and planted backdoor. 

From the "Tasks Files" button we obtained file `VanSpy.pcapng.zip` and opening the capture in Wireshark we see it is 802.11 traffic capture

![](img/20231203165526.png)

### 1. What's the name of the Wi-Fi network in the PCAP?

At this time, we can already answer first question by looking at the SSID info in the packets. We can also obtain this answer by using `aircrack-ng`, however `aircrack-ng` does not recognize `.pcapng` file format so to translate it to `.pcap` we executed:

```
tcpdump -r VanSpy.pcapng -w VanSpy.pcap
```

### 2. What's the password to access the Wi-Fi network?

Answer to second question will require bit of investigation followed by some dictionary attack on Wi-Fi password. 

To answer the first question, we used `aircrack-ng VanSpy.pcap` which showed us not only SSID but also encryption that is used: `WPA (1 handshake)`. This means that the captured traffic contains WPA handshakes and we can try guessing the password:

```
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b 22:c7:12:c7:e2:35 VanSpy.pcap
```

After a few seconds, we got our Wi-Fi password!

### 3. What suspicious tool is used by the attacker to extract a juicy file from the server?

Now things are starting to be interesting. To answer this questions, we need to find some file, or reference to some file in the captured traffic. To do that, we first need to decrypt IEEE 802.11 traffic. If we look at Wireshark under `Statistics->Protocol Hierarchy` we will see only encrypted packets:

![](img/20231203175750.png)

Luckily we know the Wi-Fi password from the previous step, which we can enter into the Wireshark to decrypt wireless traffic. In Wireshark, under `Edit->Preferences->Protocols` navigate under `IEEE 802.11`, click `Edit..` button next to `Decryption keys`. Next, under the `Key type` field select `wpa-pwd` and into the `Key` field enter the key in format `<password>:<ssid>` where `<password>` is the Wi-Fi password we found in question 2 and the `<ssid>` is the Wi-Fi name we obtained in question 1.

![](img/20231203195606.png)

After providing Wi-Fi password, Wireshark will decrypt packets and checking protocol hierarchy will show what other type of traffic was being carried through air:

![](img/20231203195832.png)

Next, let's check `Statistics->Conversations` and under `IPv4` we will see following conversations:

![](img/20231203200215.png)

Interesting is also `TCP` under same `Statistics->Conversations` menu:

![](img/20231203201149.png)

From analyzing TCP conversation we see that serve `10.0.0.2` was talking with `10.1.1.1` only over port `3389` which is port for RDP protocol. However server `10.0.0.3` has lots of conversations with `10.1.1.1` over various number of ports but with little packets exchanged... like when doing port scanning. Looking further down the TCP conversation, at the bottom we see rather familiar port `4444` that has larger number of packets exchanged.

![](img/20231203201011.png)

Port `4444` is usually used with some kind of reverse of bind shell via `nc`, so this is definitely interesting data to look at.

From above we see that the stream id for this conversation is `35` so we can right click on that and select `Apply as Filter->Selected->Filter on stream id`

![](img/20231203201802.png)

Back at the main Wireshark window, we will see only traffic related to stream `35`:

![](img/20231203201919.png)

Now, the best feature of the Wireshark (in my opinion) is `Follow TCP stream`: right click on any of packets in the main window, select `Follow->TCP stream` and Wireshark will show all printable data from the captured stream, nicely formatted, reconstructing what was exchanged between two servers where the answer to our questions is located:

![](img/20231203202617.png)

Answer is the well-known tool attacker downloaded via `wget`.

### 4. What is the case number assigned by the CyberPolice to the issues reported by McSkidy?

To answer this question, we need to ask ourselves "what this has to do with packet capture"? Because, outside of packet capture we have no other data... so it must be something else within captured traffic that we need to find out... and other than `nc` traffic there was only RDP traffic between `10.0.0.2` and `10.1.1.1`... could this be something we could look into? Also, remember the previous question "What suspicious tool is used by the attacker to **extract a juicy file from the server**?" Going back to previous TCP stream flow we can see that attacker was exporting something via:

```
cmd /c <the tool>.exe privilege::debug token::elevate crypto::capi "crypto::certificates /systemstore:LOCAL_MACHINE /store:\`"Remote Desktop\`" /export" exit
```

And at the end `base64` encoded the file:

![](img/20231203204139.png)

As a matter of fact, this is the Remote Desktop certificate on server `10.1.1.1` that contains the private key used encrypt RDP traffic. Let's get that certificate by copying the base64 text from TCP stream, decoding and saving it as `.pfx` file (base64 encoded string was shortened for readability):

```
echo 'MIIJuQIBAzCCCXUGCSqGSIb3DQEHA.......' | base64 -d > rdp.pfx
```

We can check if the file is valid PKCS #12 (`.pfx`) with following command (password is same as the `<tool name>` from question 3):

```
$ openssl pkcs12 -info -in rdp.pfx
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: TSSecKeySet1
    Microsoft CSP Name: Microsoft Enhanced Cryptographic Provider v1.0
Key Attributes
    X509v3 Key Usage: 10 
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI3rkTGlGhsO8CAggA
...
```

After we have the RDP certificate that contains private key used to encrypt RDP traffic, we need to extract just the private key:

```
openssl pkcs12 -in rdp.pfx -nocerts -out rdp_key.pem -nodes
```

After this we have the private key: `rdp_key.pem` which we can load into the Wireshark by navigating to `Edit->Preferences->Protocols->TLS`, click on `Edit...` button next to `RSA keys list` and enter `10.1.1.1` under `IP address`, `3389` under `Port`, `tpkt` under `Protocol` and path to RDP private key `rdp_key.pem` under the `Key file` field.

![](img/20231203210046.png)

It's about good time to take a rest now and get some coffee...

After we have private key to decrypt RDP traffic, we can replay it and see what was actually happening as if we're watching the video. For this we need to extract the data and process it via [PyRDP](https://github.com/GoSecure/pyrdp).

1. In the Wireshark, set display filter to `rdp` to filter all the related traffic

    ![](img/20231203212135.png)

2. Go to `File->Export PDUs to File...`, under `Display filter:` type `rdp` and select `OSI layer 7` in drop down menu and click `OK`.

    ![](img/20231203212329.png)

3. Wireshark will open in new window with only selected data, proceed saving this as new file e.g. `rdp_pdus.pcap`. 

    > NOTE: save the file as `Wireshark/tcpdump/...-pcap` rather than `.pcapng` as later we will use tool that does not recognize `.pcapng`.

4. After having the PDUs exported into `rdp_pdus.pcap` file, we can analyze it with PyRDP and see what can be found there:

    ```
    $ python pyrdp-convert.py --list-only rdp_pdus.pcap 
    [*] Analyzing PCAP 'rdp_pdus.pcap' ...
    - 10.0.0.2:55510 -> 10.1.1.1:3389 : plaintext
    ```

    > NOTE: installing and using PyRDP will not be explained here, please check the [PyRDP documentation](https://github.com/GoSecure/pyrdp).

5. Next step is to convert the `rdp_pdus.pcap` file which is essentially `Network Capture (PCAP) in Exported PDUs Layer 7 format` using the `pyrdp-convert.py`:

    ```
    $ python pyrdp-convert.py  rdp_pdus.cap

    [*] Analyzing PCAP 'rdp_pdus.pcap' ...
        - 10.0.0.2:55510 -> 10.1.1.1:3389 : plaintext
    [*] Processing 10.0.0.2:55510 -> 10.1.1.1:3389
    38% (2828 of 7405) |####################################                                               | Elapsed Time: 0:00:00 ETA:   0:00:00
    [-] Failed to handle data, continuing anyway: unpack requires a buffer of 4 bytes
    70% (5251 of 7405) |##################################################################                 | Elapsed Time: 0:00:00 ETA:   0:00:00
    [-] Failed to handle data, continuing anyway: unpack requires a buffer of 4 bytes
    98% (7271 of 7405) |#############################################################################      | Elapsed Time: 0:00:00 ETA:   0:00:00
    [-] Failed to handle data, continuing anyway: Trying to parse unknown MCS PDU type 12
    100% (7405 of 7405) |##################################################################################| Elapsed Time: 0:00:00 Time:  0:00:00

    [+] Successfully wrote '20231125145052_10.0.0.2:55510-10.1.1.1:3389.pyrdp'

    ```

6. Now we can use `pyrdp-player.py` to play the captured traffic and in get answer to our 4th question:

    ```
    $ python pyrdp-player.py 20231125145052_10.0.0.2:55510-10.1.1.1:3389.pyrdp
    [2023-12-02 10:52:30,687] - INFO - pyrdp.player - Listening for connections on 127.0.0.1:3000

    ```

    ![](img/20231204161117.png)

### 5. What is the content of the yetikey1.txt file?

Answer to the last questions is just a bit further along in the session replay we stated in the previous question. Watching the captured traffic, we will see that elf copied content of the `yetikey1.txt` file into clipboard which is captured in the metadata:

![](img/20231204161609.png)

This concludes my write-up of the first AOC 2023 Side Quest Challenge. It was interesting and I learned a lot trying to solve these questions. Interestingly the most frustrating one where I spend most of the time was finding the top right QR code :smiley:.

## References

1. https://www.aircrack-ng.org/doku.php?id=cracking_wpa
2. https://unit42.paloaltonetworks.com/wireshark-tutorial-decrypting-rdp-traffic/
3. https://miloserdov.org/?p=2525
4. https://github.com/GoSecure/pyrdp
4. https://res260.medium.com/ihack-2020-monster-inc-the-middle-rdp-network-forensics-writeup-91e2fb0f4287



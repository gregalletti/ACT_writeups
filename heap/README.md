# bcloud ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
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
**flag{house_of_force_once_again!}**

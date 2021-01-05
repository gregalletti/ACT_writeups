# john ![c](https://img.shields.io/badge/solved-success)
### Analysis & Exploit
First of all let's analyze the source with `file`: cool, it's a 32-bit stripped ELF.

We open *Ghidra* and search for the main through the `entry()` function, and search for the first instruction address: `0x0804985b`

We can look at the assembly code either from Ghidra or from **gdb** with: `x /50i 0x0804985b`
```assembly
   0x804985b:	lea    ecx,[esp+0x4]
   0x804985f:	and    esp,0xfffffff0
   0x8049862:	push   DWORD PTR [ecx-0x4]
   0x8049865:	push   ebp
   0x8049866:	mov    ebp,esp
   0x8049868:	push   ecx
   0x8049869:	sub    esp,0x4
   0x804986c:	mov    eax,ecx
   0x804986e:	push   DWORD PTR [eax+0x4]
   0x8049871:	push   DWORD PTR [eax]
   0x8049873:	push   0x53
 $ 0x8049878:	push   0x804970e 
   0x804987d:	call   0x804922b
```
We see a weird function, let's see what it calls: from gdb we see call 0x804922b
After some rewriting with Ghidra we can see call decrypt_code

Let's see what it does from Ghidra: after a memprotect on a 0x1000 size section with READ, WRITE, EXEC (7) it does something more interesting (gdb: x /50i 0x804922b)
```assembly
   0x804922b:	push   ebp
   0x804922c:	mov    ebp,esp
   0x804922e:	sub    esp,0x8
   0x8049231:	mov    eax,DWORD PTR [ebp+0x8]
   0x8049234:	and    eax,0xfffff000
   0x8049239:	sub    esp,0x4
   0x804923c:	push   0x7
   0x804923e:	push   0x1000
   0x8049243:	push   eax
   0x8049244:	call   0x8049040 <mprotect@plt>
   0x8049249:	add    esp,0x10
   0x804924c:	mov    ecx,DWORD PTR [ebp+0x8]
   0x804924f:	mov    edx,0x66666667
   0x8049254:	mov    eax,ecx
   0x8049256:	imul   edx
   0x8049258:	sar    edx,1
   0x804925a:	mov    eax,ecx
   0x804925c:	sar    eax,0x1f
   0x804925f:	sub    edx,eax
   0x8049261:	mov    eax,edx
   0x8049263:	mov    edx,eax
   0x8049265:	shl    edx,0x2
   0x8049268:	add    edx,eax
   0x804926a:	mov    eax,ecx
   0x804926c:	sub    eax,edx
   0x804926e:	mov    edx,DWORD PTR [eax*4+0x804c03c]
   0x8049275:	mov    eax,DWORD PTR [ebp+0x8]
   0x8049278:	mov    ecx,DWORD PTR [ebp+0xc]
   0x804927b:	add    esp,0x8
   0x804927e:	push   eax
   0x804927f:	mov    edx,DWORD PTR [edx]
   0x8049281:	xor    DWORD PTR [eax],edx
   0x8049283:	add    eax,0x4
   0x8049286:	dec    ecx
   0x8049287:	jne    0x8049281
   0x8049289:	pop    eax
   0x804928a:	call   eax
```

It does a lot of operations and then a call eax is present, so we set a breakpoint to that address and see what it contains

b * 0x804928a => eax = 0x804970e THIS IS THE SAME VALUE WE PUSHED IN THE MAIN FUNCTION BEFORE THE CALL decrypt_code ($)

Let's step in the function (si), and then dump the next instructions (x /100i $eip)
```assembly
=> 0x804970e:	push   ebp
   0x804970f:	mov    ebp,esp
   0x8049711:	sub    esp,0x18
   0x8049714:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8049718:	jg     0x804973a
   0x804971a:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804971d:	mov    eax,DWORD PTR [eax]
   0x804971f:	sub    esp,0x8
   0x8049722:	push   eax
   0x8049723:	push   0x804a0f8
   0x8049728:	call   0x8049050 <printf@plt>
   0x804972d:	add    esp,0x10
   0x8049730:	sub    esp,0xc
   0x8049733:	push   0x0
   0x8049735:	call   0x8049080 <exit@plt>
   0x804973a:	mov    DWORD PTR [ebp-0xc],0x0
   0x8049741:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049744:	add    eax,0x4
   0x8049747:	mov    eax,DWORD PTR [eax]
   0x8049749:	sub    esp,0x4
   0x804974c:	push   eax
   0x804974d:	push   0x11
   0x8049752:	push   0x80492a0
   0x8049757:	call   0x804922b
```
That's cool, but we can see that we have another decrypt_code call at the end: this is not finished yet

By looking at the next 200 instructions we can see that the decrypting routine is called 7 times in total
```assembly
=> 0x804970e:	push   ebp
   0x804970f:	mov    ebp,esp
   0x8049711:	sub    esp,0x18
   0x8049714:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8049718:	jg     0x804973a
   0x804971a:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804971d:	mov    eax,DWORD PTR [eax]
   0x804971f:	sub    esp,0x8
   0x8049722:	push   eax
   0x8049723:	push   0x804a0f8
   0x8049728:	call   0x8049050 <printf@plt>
   0x804972d:	add    esp,0x10
   0x8049730:	sub    esp,0xc
   0x8049733:	push   0x0
   0x8049735:	call   0x8049080 <exit@plt>
   0x804973a:	mov    DWORD PTR [ebp-0xc],0x0
   0x8049741:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049744:	add    eax,0x4
   0x8049747:	mov    eax,DWORD PTR [eax]
   0x8049749:	sub    esp,0x4
   0x804974c:	push   eax
   0x804974d:	push   0x11
   0x8049752:	push   0x80492a0
   0x8049757:	call   0x804922b ================================= #1
   0x804975c:	add    esp,0x10
   0x804975f:	add    DWORD PTR [ebp-0xc],eax
   0x8049762:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049765:	add    eax,0x4
   0x8049768:	mov    eax,DWORD PTR [eax]
   0x804976a:	sub    esp,0x4
   0x804976d:	push   eax
   0x804976e:	push   0x11
   0x8049773:	push   0x80492e5
   0x8049778:	call   0x804922b ================================= #2
   0x804977d:	add    esp,0x10
   0x8049780:	add    DWORD PTR [ebp-0xc],eax
   0x8049783:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049786:	add    eax,0x4
   0x8049789:	mov    eax,DWORD PTR [eax]
   0x804978b:	sub    esp,0x4
   0x804978e:	push   eax
   0x804978f:	push   0x17
   0x8049794:	push   0x8049329
   0x8049799:	call   0x804922b ================================= #3
   0x804979e:	add    esp,0x10
   0x80497a1:	add    DWORD PTR [ebp-0xc],eax
   0x80497a4:	mov    eax,DWORD PTR [ebp+0x1c]
   0x80497a7:	add    eax,0x4
   0x80497aa:	mov    eax,DWORD PTR [eax]
   0x80497ac:	sub    esp,0x4
   0x80497af:	push   eax
   0x80497b0:	push   0x18
   0x80497b5:	push   0x80496ab
   0x80497ba:	call   0x804922b ================================= #4
   0x80497bf:	add    esp,0x10
   0x80497c2:	add    DWORD PTR [ebp-0xc],eax
   0x80497c5:	mov    eax,DWORD PTR [ebp+0x1c]
   0x80497c8:	add    eax,0x4
   0x80497cb:	mov    eax,DWORD PTR [eax]
   0x80497cd:	sub    esp,0x4
   0x80497d0:	push   eax
   0x80497d1:	push   0x31
   0x80497d6:	push   0x80495e4
   0x80497db:	call   0x804922b ================================= #5
   0x80497e0:	add    esp,0x10
   0x80497e3:	add    DWORD PTR [ebp-0xc],eax
   0x80497e6:	mov    eax,DWORD PTR [ebp+0x1c]
   0x80497e9:	add    eax,0x4
   0x80497ec:	mov    eax,DWORD PTR [eax]
   0x80497ee:	push   0x0
   0x80497f0:	push   eax
   0x80497f1:	push   0x27
   0x80497f6:	push   0x8049546
   0x80497fb:	call   0x804922b ================================= #6
   0x8049800:	add    esp,0x10
   0x8049803:	add    DWORD PTR [ebp-0xc],eax
   0x8049806:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049809:	add    eax,0x4
   0x804980c:	mov    eax,DWORD PTR [eax]
   0x804980e:	sub    esp,0x4
   0x8049811:	push   eax
   0x8049812:	push   0x9
   0x8049817:	push   0x804951f
   0x804981c:	call   0x804922b ================================= #7
   0x8049821:	add    esp,0x10
   0x8049824:	add    DWORD PTR [ebp-0xc],eax
   0x8049827:	cmp    DWORD PTR [ebp-0xc],0x7
 € 0x804982b:	jne    0x8049848
   0x804982d:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049830:	add    eax,0x4
   0x8049833:	mov    eax,DWORD PTR [eax]
   0x8049835:	sub    esp,0x8
   0x8049838:	push   eax
   0x8049839:	push   0x804a110
   0x804983e:	call   0x8049050 <printf@plt>
   0x8049843:	add    esp,0x10
   0x8049846:	jmp    0x8049858
   0x8049848:	sub    esp,0xc0x8049329
   0x804984b:	push   0x804a138
   0x8049850:	call   0x8049050 <printf@plt>
   0x8049855:	add    esp,0x10
   0x8049858:	nop
   0x8049859:	leave  
   0x804985a:	ret  
```
After that weird routine we can see two different printf calls: one must be the success and the other the failure 
In fact, at (€) we see a jne    0x8049848, that if taken will avoid the first printf reaching the second one

Now, let's figure out what is in the argument passed everytime we call the decrypting routine

1. 0x80492a0
2. 0x80492e5
3. 0x8049329
4. 0x80496ab
5. 0x80495e4
6. 0x8049546
7. 0x804951f

To do that, just add a breakpoint at those addresses

#1 ==================================================

- b * 0x80492a0
- x /50i $eip
```assembly
=> 0x80492a0:	adc    DWORD PTR [ecx+0x18ec83e5],ecx
   0x80492a6:	sub    esp,0x8
   0x80492a9:	push   0x804a039
   0x80492ae:	push   DWORD PTR [ebp+0x18]
   0x80492b1:	call   0x8049030 <strstr@plt>
   0x80492b6:	add    esp,0x10
   0x80492b9:	mov    DWORD PTR [ebp-0xc],eax
   0x80492bc:	mov    eax,DWORD PTR [ebp-0xc]
   0x80492bf:	cmp    eax,DWORD PTR [ebp+0x18]
   0x80492c2:	jne    0x80492cb
   0x80492c4:	mov    eax,0x1
   0x80492c9:	jmp    0x80492e3
   0x80492cb:	sub    esp,0x8
   0x80492ce:	push   DWORD PTR [ebp+0x18]
   0x80492d1:	push   0x804a03f
   0x80492d6:	call   0x8049050 <printf@plt>
   0x80492db:	add    esp,0x10
   0x80492de:	mov    eax,0x0
   0x80492e3:	leave  
   0x80492e4:	ret    
```
#2 ==================================================

- b * 0x80492e5

After putting this breakpoint and continuing we get a SEGFAULT, this is because we are using a software breakpoint as 0xCC, and the unpacking will mess everything up with this byte, so let's use some hardware breakpoints: no idea on how to do this (hbreak?)

Yes hbreak, but before that let's close gdb and reopen it, and then use the 'start' command, then 
- hbreak * 0x80492e5

- x /50i $eip
```assembly
=> 0x80492e5:	push   ebp
   0x80492e6:	mov    ebp,esp
   0x80492e8:	sub    esp,0x8
   0x80492eb:	sub    esp,0xc
   0x80492ee:	push   DWORD PTR [ebp+0x18]
   0x80492f1:	call   0x8049090 <strlen@plt>
   0x80492f6:	add    esp,0x10
   0x80492f9:	lea    edx,[eax-0x1]
   0x80492fc:	mov    eax,DWORD PTR [ebp+0x18]
   0x80492ff:	add    eax,edx
   0x8049301:	movzx  eax,BYTE PTR [eax]
   0x8049304:	cmp    al,0x7d
   0x8049306:	jne    0x804930f
   0x8049308:	mov    eax,0x1
   0x804930d:	jmp    0x8049327
   0x804930f:	sub    esp,0x8
   0x8049312:	push   DWORD PTR [ebp+0x18]
   0x8049315:	push   0x804a054
   0x804931a:	call   0x8049050 <printf@plt>
   0x804931f:	add    esp,0x10
   0x8049322:	mov    eax,0x0
   0x8049327:	leave  
   0x8049328:	ret    
```
cmp    al,0x7d tells us that the last character must be a 0x7d = }
we can chek it by printing the parameter pushed just before the printf call.

#3 ==================================================

- hbreak * 0x8049329

- x /50i $eip
```assembly
=> 0x8049329:	push   ebp
   0x804932a:	mov    ebp,esp
   0x804932c:	sub    esp,0x18
   0x804932f:	sub    esp,0xc
   0x8049332:	push   DWORD PTR [ebp+0x18]
   0x8049335:	call   0x8049090 <strlen@plt>
   0x804933a:	add    esp,0x10
   0x804933d:	mov    DWORD PTR [ebp-0xc],eax
   0x8049340:	mov    DWORD PTR [ebp-0x10],0x0
   0x8049347:	jmp    0x8049376
   0x8049349:	mov    edx,DWORD PTR [ebp-0x10]
   0x804934c:	mov    eax,DWORD PTR [ebp+0x18]
   0x804934f:	add    eax,edx
   0x8049351:	movzx  eax,BYTE PTR [eax]
   0x8049354:	test   al,al
   0x8049356:	jns    0x8049372
   0x8049358:	sub    esp,0x8
   0x804935b:	push   DWORD PTR [ebp+0x18]
   0x804935e:	push   0x804a066
   0x8049363:	call   0x8049050 <printf@plt>
   0x8049368:	add    esp,0x10
   0x804936b:	mov    eax,0x0
   0x8049370:	jmp    0x8049383
   0x8049372:	add    DWORD PTR [ebp-0x10],0x1
   0x8049376:	mov    eax,DWORD PTR [ebp-0x10]
   0x8049379:	cmp    eax,DWORD PTR [ebp-0xc]
   0x804937c:	jl     0x8049349
   0x804937e:	mov    eax,0x1
   0x8049383:	leave  
   0x8049384:	ret    
```
Sometimes is better to start from the easiest part. In fact if we access the parameter passed to the printf we can see that this section only checks if there are all ASCII characters: we avoided looking at all the instructions


#4 ==================================================

- hbreak * 0x80496ab

- x /50i $eip
```assembly
=> 0x80496ab:	push   ebp
   0x80496ac:	mov    ebp,esp
   0x80496ae:	push   ebx
   0x80496af:	sub    esp,0x14
   0x80496b2:	mov    DWORD PTR [ebp-0xc],0x6
   0x80496b9:	mov    DWORD PTR [ebp-0x10],0x1
   0x80496c0:	jmp    0x80496fc
   0x80496c2:	mov    eax,DWORD PTR [ebp-0x10]
   0x80496c5:	add    eax,0x4
   0x80496c8:	mov    edx,eax
   0x80496ca:	mov    eax,DWORD PTR [ebp+0x18]
   0x80496cd:	add    eax,edx
   0x80496cf:	movzx  eax,BYTE PTR [eax]
   0x80496d2:	movsx  ebx,al
   0x80496d5:	sub    esp,0x4
   0x80496d8:	push   DWORD PTR [ebp-0x10]
   0x80496db:	push   0x36
   0x80496e0:	push   0x8049385
   0x80496e5:	call   0x804922b
   0x80496ea:	add    esp,0x10
   0x80496ed:	cmp    ebx,eax
   0x80496ef:	je     0x80496f8
   0x80496f1:	mov    eax,0x0
   0x80496f6:	jmp    0x8049709
   0x80496f8:	add    DWORD PTR [ebp-0x10],0x1
   0x80496fc:	mov    eax,DWORD PTR [ebp-0x10]
   0x80496ff:	cmp    eax,DWORD PTR [ebp-0xc]
   0x8049702:	jle    0x80496c2
   0x8049704:	mov    eax,0x1
   0x8049709:	mov    ebx,DWORD PTR [ebp-0x4]
   0x804970c:	leave  
   0x804970d:	ret    
```
Ah shit, here we go again.. anothe decrypt_code call 
Let's do it again, removing the breakpoints for what we already completed

-- hb * 0x8049385

-- x /150i $eip
```assembly
=> 0x8049385:	push   ebp
   0x8049386:	mov    ebp,esp
   0x8049388:	sub    esp,0x28
   0x804938b:	fild   DWORD PTR [ebp+0x18]
   0x804938e:	fld    QWORD PTR ds:0x804a150
   0x8049394:	lea    esp,[esp-0x8]
   0x8049398:	fstp   QWORD PTR [esp]
   0x804939b:	lea    esp,[esp-0x8]
   0x804939f:	fstp   QWORD PTR [esp]
   0x80493a2:	call   0x8049060 <pow@plt>
   0x80493a7:	add    esp,0x10
   0x80493aa:	fld    QWORD PTR ds:0x804a158
   0x80493b0:	fmulp  st(1),st
   0x80493b2:	fstp   QWORD PTR [ebp-0x28]
   0x80493b5:	fild   DWORD PTR [ebp+0x18]
   0x80493b8:	fld    QWORD PTR ds:0x804a160
   0x80493be:	lea    esp,[esp-0x8]
   0x80493c2:	fstp   QWORD PTR [esp]
   0x80493c5:	lea    esp,[esp-0x8]
   0x80493c9:	fstp   QWORD PTR [esp]
   0x80493cc:	call   0x8049060 <pow@plt>
   0x80493d1:	add    esp,0x10
   0x80493d4:	fld    QWORD PTR ds:0x804a168
   0x80493da:	fmulp  st(1),st
   0x80493dc:	fsubr  QWORD PTR [ebp-0x28]
   0x80493df:	fstp   QWORD PTR [ebp-0x28]
   0x80493e2:	fild   DWORD PTR [ebp+0x18]
   0x80493e5:	fld    QWORD PTR ds:0x804a170
   0x80493eb:	lea    esp,[esp-0x8]
   0x80493ef:	fstp   QWORD PTR [esp]
   0x80493f2:	lea    esp,[esp-0x8]
   0x80493f6:	fstp   QWORD PTR [esp]
   0x80493f9:	call   0x8049060 <pow@plt>
   0x80493fe:	add    esp,0x10
   0x8049401:	fld    QWORD PTR ds:0x804a178
   0x8049407:	fmulp  st(1),st
   0x8049409:	fadd   QWORD PTR [ebp-0x28]
   0x804940c:	fstp   QWORD PTR [ebp-0x28]
   0x804940f:	fild   DWORD PTR [ebp+0x18]
   0x8049412:	fld    QWORD PTR ds:0x804a180
   0x8049418:	lea    esp,[esp-0x8]
   0x804941c:	fstp   QWORD PTR [esp]
   0x804941f:	lea    esp,[esp-0x8]
   0x8049423:	fstp   QWORD PTR [esp]
   0x8049426:	call   0x8049060 <pow@plt>
   0x804942b:	add    esp,0x10
   0x804942e:	fld    QWORD PTR ds:0x804a188
   0x8049434:	fmulp  st(1),st
   0x8049436:	fld    QWORD PTR [ebp-0x28]
   0x8049439:	fsubp  st(1),st
   0x804943b:	fild   DWORD PTR [ebp+0x18]
   0x804943e:	fld    QWORD PTR ds:0x804a190
   0x8049444:	fmulp  st(1),st
   0x8049446:	faddp  st(1),st
   0x8049448:	fld    QWORD PTR ds:0x804a198
   0x804944e:	faddp  st(1),st
   0x8049450:	fstp   DWORD PTR [ebp-0xc]
   0x8049453:	movss  xmm0,DWORD PTR [ebp-0xc]
   0x8049458:	cvttss2si eax,xmm0
   0x804945c:	leave  
   0x804945d:	ret  
```
No way I'm gonna try to solve this, so let's get smarter: in the outer function we have    0x80496ed:	cmp    ebx,eax
Set another breakpoint to that address and try to analyze the situation:

ebx = 0x41 ('A')
eax = 0x70 ('p')

so the first letter must be a 'p', in fact by continuing the program it stops saying "Loser". Now let's pass flag{pAAAA} and go on.

at the next iteration we have

ebx = 0x41 ('A')
eax = 0x61 ('a')

then
eax = 0x63 ('c')
eax = 0x6b ('k')
eax = 0x65 ('e')
eax = 0x72 ('r')

So we have a partial flag like flag{packer}



#5 ==================================================

- hbreak * 0x80495e4

- x /50i $eip
```assembly
=> 0x80495e4:	push   ebp
   0x80495e5:	mov    ebp,esp
   0x80495e7:	push   edi
   0x80495e8:	push   esi
   0x80495e9:	push   ebx
   0x80495ea:	sub    esp,0x8c
   0x80495f0:	mov    eax,DWORD PTR [ebp+0x18]
   0x80495f3:	mov    DWORD PTR [ebp-0x8c],eax
   0x80495f9:	mov    eax,gs:0x14
   0x80495ff:	mov    DWORD PTR [ebp-0x1c],eax
   0x8049602:	xor    eax,eax
   0x8049604:	lea    eax,[ebp-0x78]
   0x8049607:	mov    ebx,0x804a0a0
   0x804960c:	mov    edx,0x16
   0x8049611:	mov    edi,eax
   0x8049613:	mov    esi,ebx
   0x8049615:	mov    ecx,edx
   0x8049617:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x8049619:	mov    DWORD PTR [ebp-0x7c],0x0
   0x8049620:	jmp    0x8049687
   0x8049622:	mov    eax,DWORD PTR [ebp-0x7c]
   0x8049625:	mov    edx,DWORD PTR [ebp+eax*8-0x74]
   0x8049629:	mov    eax,DWORD PTR [ebp+eax*8-0x78]
   0x804962d:	mov    ecx,DWORD PTR [ebp-0x7c]
   0x8049630:	add    ecx,0xb
   0x8049633:	mov    ebx,ecx
   0x8049635:	mov    ecx,DWORD PTR [ebp-0x8c]
   0x804963b:	add    ecx,ebx
   0x804963d:	movzx  ecx,BYTE PTR [ecx]
   0x8049640:	movsx  ecx,cl
   0x8049643:	sub    esp,0xc
   0x8049646:	push   edx
   0x8049647:	push   eax
   0x8049648:	push   ecx
   0x8049649:	push   0x30
   0x804964e:	push   0x804945e
   0x8049653:	call   0x804922b
   0x8049658:	add    esp,0x20
   0x804965b:	test   eax,eax
   0x804965d:	jne    0x8049666
   0x804965f:	mov    eax,0x0
   0x8049664:	jmp    0x8049692
   0x8049666:	mov    eax,DWORD PTR [ebp-0x8c]
   0x804966c:	add    eax,0x11
   0x804966f:	movzx  eax,BYTE PTR [eax]
   0x8049672:	movsx  eax,al
   0x8049675:	and    eax,0x1
   0x8049678:	test   eax,eax
   0x804967a:	jne    0x8049683
   0x804967c:	mov    eax,0x0
   0x8049681:	jmp    0x8049692
   0x8049683:	add    DWORD PTR [ebp-0x7c],0x1
   0x8049687:	cmp    DWORD PTR [ebp-0x7c],0xa
   0x804968b:	jle    0x8049622
   0x804968d:	mov    eax,0x1
   0x8049692:	mov    edx,DWORD PTR [ebp-0x1c]
   0x8049695:	xor    edx,DWORD PTR gs:0x14
   0x804969c:	je     0x80496a3
   0x804969e:	call   0x8049070 <__stack_chk_fail@plt>
   0x80496a3:	lea    esp,[ebp-0xc]
   0x80496a6:	pop    ebx
   0x80496a7:	pop    esi
   0x80496a8:	pop    edi
   0x80496a9:	pop    ebp
   0x80496aa:	ret    
```
Unpacking AGAIN.

   0x8049687:	cmp    DWORD PTR [ebp-0x7c],0xa
   0x804968b:	jle    0x8049622
These rows tell us that we will loop and check for 0xa = 10 times +1, so 11 characters

-- hb * 0x804945e

We have some fancy operations again, with sqrt() and pow() 
```assembly
=> 0x804945e:	push   ebp
   0x804945f:	mov    ebp,esp
   0x8049461:	sub    esp,0x38
   0x8049464:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049467:	mov    DWORD PTR [ebp-0x20],eax
   0x804946a:	mov    eax,DWORD PTR [ebp+0x20]
   0x804946d:	mov    DWORD PTR [ebp-0x1c],eax
   0x8049470:	fild   DWORD PTR [ebp+0x18]
   0x8049473:	sub    esp,0x8
   0x8049476:	lea    esp,[esp-0x8]
   0x804947a:	fstp   QWORD PTR [esp]
   0x804947d:	call   0x80490b0 <sqrt@plt>
   0x8049482:	add    esp,0x10
   0x8049485:	fild   DWORD PTR [ebp+0x18]
   0x8049488:	fxch   st(1)
   0x804948a:	sub    esp,0x8
   0x804948d:	lea    esp,[esp-0xc]
   0x8049491:	fstp   TBYTE PTR [esp]
   0x8049494:	lea    esp,[esp-0xc]
   0x8049498:	fstp   TBYTE PTR [esp]
   0x804949b:	call   0x80490c0 <powl@plt>
   0x80494a0:	add    esp,0x20
   0x80494a3:	fld    TBYTE PTR ds:0x804a1a0
   0x80494a9:	fxch   st(1)
   0x80494ab:	fcomi  st,st(1)
   0x80494ad:	fstp   st(1)
   0x80494af:	jae    0x80494d0
   0x80494b1:	fnstcw WORD PTR [ebp-0x22]
   0x80494b4:	movzx  eax,WORD PTR [ebp-0x22]
   0x80494b8:	or     ah,0xc
   0x80494bb:	mov    WORD PTR [ebp-0x24],ax
   0x80494bf:	fldcw  WORD PTR [ebp-0x24]
   0x80494c2:	fistp  QWORD PTR [ebp-0x30]
   0x80494c5:	fldcw  WORD PTR [ebp-0x22]
   0x80494c8:	mov    eax,DWORD PTR [ebp-0x30]
   0x80494cb:	mov    edx,DWORD PTR [ebp-0x2c]
   0x80494ce:	jmp    0x80494fb
   0x80494d0:	fld    TBYTE PTR ds:0x804a1a0
   0x80494d6:	fsubrp st(1),st
   0x80494d8:	fnstcw WORD PTR [ebp-0x22]
   0x80494db:	movzx  eax,WORD PTR [ebp-0x22]
   0x80494df:	or     ah,0xc
   0x80494e2:	mov    WORD PTR [ebp-0x24],ax
   0x80494e6:	fldcw  WORD PTR [ebp-0x24]
   0x80494e9:	fistp  QWORD PTR [ebp-0x30]
   0x80494ec:	fldcw  WORD PTR [ebp-0x22]
   0x80494ef:	mov    eax,DWORD PTR [ebp-0x30]
   0x80494f2:	mov    edx,DWORD PTR [ebp-0x2c]
   0x80494f5:	xor    edx,0x80000000
   0x80494fb:	add    eax,0x15
   0x80494fe:	adc    edx,0x0
   0x8049501:	mov    DWORD PTR [ebp-0x10],eax
   0x8049504:	mov    DWORD PTR [ebp-0xc],edx
   0x8049507:	mov    eax,DWORD PTR [ebp-0x10]
   0x804950a:	mov    edx,DWORD PTR [ebp-0xc]
   0x804950d:	xor    eax,DWORD PTR [ebp-0x20]
   0x8049510:	xor    edx,DWORD PTR [ebp-0x1c]
   0x8049513:	or     eax,edx
   0x8049515:	test   eax,eax
   0x8049517:	sete   al
   0x804951a:	movzx  eax,al
   0x804951d:	leave  
   0x804951e:	ret 
```
But by looking at these 2 lines 
   0x80494ab:	fcomi  st,st(1)
   ...
   0x80494af:	jae    0x80494d0
we see that this fcomi will change the outcome of the jump above equal after that.

FCOMI st,st(1) is a floating point comparison between st(0) and st(1)
- st(0) > st(1) : CF = 0
- st(0) < st(1) : CF = 1
- st(0) = st(1) : CF = 0

JAE will jump if the flag CF == 0, so we must reach the address 0x80494ab with st(0) < st(1), wew don't want to jump here.

Let's see with some values what st0 and st1 look like, by setting a breakpoint:

-- hb * 0x80494ab

with input flag{packerAAAA} we can't pass the check, so we try to use another character

_ flag{packerBAAA}, nothing again

_ flag{packer@AAA}, YES st0 < st1, so we must stay under the 'A' ASCII character (numbers and symbols)

Honestly, here we try to bruteforce every following character. The check is in the outer code.

0x804965b -> hb * 0x804965d is better because we can see if the jump is taken or not
0x8049678

So far the flag is flag{packer-4_3-1337}

#6 ==================================================

- hb * 0x8049546

- x /50i $eip
```assembly
=> 0x8049546:	push   ebp
   0x8049547:	mov    ebp,esp
   0x8049549:	push   ebx
   0x804954a:	sub    esp,0x14
   0x804954d:	mov    DWORD PTR [ebp-0xc],0x804a081
   0x8049554:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049557:	add    eax,0x16
   0x804955a:	mov    ebx,eax 							ebx = 0x16
   0x804955c:	sub    esp,0xc
   0x804955f:	push   DWORD PTR [ebp+0x18]				
   0x8049562:	call   0x8049090 <strlen@plt>			eax = strlen(input)
   0x8049567:	add    esp,0x10
   0x804956a:	cmp    ebx,eax 							confronta la lunghezza dell'input con ebx
   0x804956c:	jb     0x8049575  						se ebx < eax salta sotto, qundi non finisce il loop
   0x804956e:	mov    eax,0x1
   0x8049573:	jmp    0x80495df 						queste due istruzioni sono la fine, quando diventa ebx = eax
   0x8049575:	mov    edx,DWORD PTR [ebp+0x1c]
   0x8049578:	mov    eax,DWORD PTR [ebp-0xc]
   0x804957b:	add    eax,edx
   0x804957d:	movzx  ecx,BYTE PTR [eax]
   0x8049580:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049583:	lea    edx,[eax+0x14]
   0x8049586:	mov    eax,DWORD PTR [ebp+0x18]
   0x8049589:	add    eax,edx
   0x804958b:	movzx  eax,BYTE PTR [eax]
   0x804958e:	xor    eax,ecx
   0x8049590:	mov    BYTE PTR [ebp-0xe],al
   0x8049593:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049596:	add    eax,0x15
   0x8049599:	mov    edx,eax
   0x804959b:	mov    eax,DWORD PTR [ebp+0x18]
   0x804959e:	add    eax,edx
   0x80495a0:	movzx  eax,BYTE PTR [eax]
   0x80495a3:	mov    BYTE PTR [ebp-0xd],al
   0x80495a6:	movzx  eax,BYTE PTR [ebp-0xe]
   0x80495aa:	cmp    al,BYTE PTR [ebp-0xd]
   0x80495ad:	je     0x80495b6
   0x80495af:	mov    eax,0x0
   0x80495b4:	jmp    0x80495df
   0x80495b6:	mov    eax,DWORD PTR [ebp+0x1c]
   0x80495b9:	add    eax,0x1
   0x80495bc:	sub    esp,0x8
   0x80495bf:	push   eax
   0x80495c0:	push   DWORD PTR [ebp+0x18]
   0x80495c3:	push   0xdeadb00b
   0x80495c8:	push   0xdeadb00b
   0x80495cd:	push   0xdeadb00b
   0x80495d2:	push   0xdeadb00b
   0x80495d7:	call   0x8049546 						torna all'inizio (ricorsione)
   0x80495dc:	add    esp,0x20
   0x80495df:	mov    ebx,DWORD PTR [ebp-0x4]
   0x80495e2:	leave  
   0x80495e3:	ret    
```
We can easily see that this is a recursive function, in fact it calls itself near the end.

Those 2 lines are the most important one:
   0x80495aa:	cmp    al,BYTE PTR [ebp-0xd]
   0x80495ad:	je     0x80495b6

because the next one is
   0x80495af:	mov    eax,0x0
so we want to avoid that, by taking the jump on equal.

Again let's put a breakpoint in 0x80495aa and explore the situation


INPUT: flag{packer-4_3-1337AAAAAAAA}

pwndbg> info reg
eax            0x4a	===== 'J'
eax            0xd	===== carriage return, mmm
eax            0x4e	===== 'N'
eax            0x41	===== 'A'
eax            0x40	===== '@'
eax            0x57	===== 'W'


INPUT: flag{packer-4_3-1337BBBBBBBB}

pwndbg> info reg
eax            0x49	===== 'I'
eax            0xe	===== 
eax            0x4e	===== 'N'
eax            0x41	===== 'A'
eax            0x40	===== '@'
eax            0x57	===== 'W'


INPUT: flag{packer-4_3-1337CCCCCCCC}

0x48

and so on...

the problem is with the second value, that increases when the first one decreases, so when the input increases

Let's try with a bigger input in order to reach a printable character (> 0x20)

INPUT: flag{packer-4_3-1337aaaaaaaa}

pwndbg> info reg
eax            0x6a	===== 'j'
eax            0x2d	===== '-'
eax            0x4e	===== 'N'
eax            0x41	===== 'A'
eax            0x40	===== '@'
eax            0x57	===== 'W'


INPUT: flag{packer-4_3-1337-AAAAAAAAA}

pwndbg> info reg
eax            0x26	===== '&'
eax            0x6a	===== 'j'
eax            0x65	===== 'e'
eax            0x65	===== 'e'
eax            0x64	===== 'd'
eax            0x72	===== 'r'
eax            0x62	===== 'b'
eax            0x65	===== 'e'
eax            0x6c	===== 'l'
eax            0x54	===== 'T'
eax            0x54	===== 'T'

INPUT: flag{packer-4_3-1337_AAAAAAAAA}

pwndbg> info reg
eax            0x54	===== 'T'
eax            0x6a	===== 'j'
eax            0x65	===== 'e'
eax            0x65	===== 'e'
eax            0x64	===== 'd'
eax            0x72	===== 'r'
eax            0x62	===== 'b'
eax            0x65	===== 'e'
eax            0x6c	===== 'l'
eax            0x54	===== 'T'
eax            0x54	===== 'T'


WAAAAAAAAAAAAAAAAAAAAAAIT: i failed before: flag must be changed with: flag{packer-4_3-1337\&-AAAAA} because test #5 was failing (\ is for escaping)

flag{packer-4_3-1337\&-AAAAAAAAA}


pwndbg> info reg
eax            0x2d	===== '-' (already passed)
eax            0x61	===== 'a'
eax            0x6e	===== 'n'
eax            0x6e	===== 'n'
eax            0x6f	===== 'o'
eax            0x79	===== 'y'
eax            0x	===== 'i'
eax            0x	===== 'n'
eax            0x67	===== 'g'
eax            0x5f	===== '_'
eax            0x5f	===== '_'
eax            0x5f	===== '_'

**flag{packer-4_3-1337\&-annoying__}**

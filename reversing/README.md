# revmem ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit


# revmemp ![c](https://img.shields.io/badge/solved-success)
### Analysis
Abbiamo analizzato il file -> STRIPPED
Apriamolo su GDB, runniamolo una prima volta altrimenti impazzisce e poi facciamo INFO FILES: possiamo vedere l'entry point.

Mettiamo un break a quell'indirizzo, così siamo appena prima della chiamata a libc_start_main
Ora guardiamo le prossime istruzioni in memoria con x /200i $rip
Possiamo vedere tante chiamate a funzioni note, con i relativi indirizzi.

Dall'analisi con Ghidra sappiamo dove NON dobbiamo arrivare: 
1) la prima chiamata alla funzione in 0x555...555199 ci darà exit(-1) -> PRIMA DEL PRIMO WHILE, PRIMA ISTRUZIONE DEL MAIN 
2) una chiamata a ptrace e il controllo del valore di ritorno ci darà exit(-1) -> PRIMA DI TUTTO
3) la seconda chiamata alla funzione in 0x555...555199 ci darà exit(-1) -> PRIMA DI RAND, È DENTRO A UN WHILE RIPETUTO
PER 32 VOLTE (32 CARATTERI DELLA FLAG)

### Exploit
2) Sappiamo che ptrace viene eseguita subito, quindi dalla schermata di prima troviamo l'indirizzo in cui viene fatta
la chiamata, e ci mettiamo un breakpoint: ora facciamo set $rip = 0x... per saltare direttamente la chiamata e andare
all'indirizzo di ritorno di questa funzione.

1) Guardiamo dove viene chiamata e mettiamo un breakpoint all'indirizzo, e poi semplicemente settiamo l'rip all'istruzione
dopo saltando la chiamata cattiva.

3) Con lo stesso procedimento mettiamo un breakpoint all'indirizzo prima della rand, e poi semplicemente settiamo l'rip
con appunto la rand, saltando la chiamata cattiva. Va fatto un bel po' di volte, sicuramente c'è un altro modo

A questo punto già vediamo la flag su gdb, ma se vogliamo comunque possiamo mettere un breakpoint alla strncmp e
analizzare direttamente i registri

**flag{this_was_a_bit_more_complex}**

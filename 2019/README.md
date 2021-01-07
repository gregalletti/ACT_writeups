## keycheck_baby
After a rapid analysis we can see that it's a classic input guessing challenge. We can open it with Ghidra, and with a simple Python script we easily get the first part of the flag: flag{y0u_d4_qu33n_

Here it comes the first problem: even with Ghidra, the second input check seems unsolvable. 

For this reason I dropped the idea of understanding the code, and moved on angr to solve the challenge with symbolic execution.

With a basic script we can retrieve the flag, that is: flag{y0u_d4_qu33n_0f_c4ck1ngz}

## lolshop
This is a serialization challenge, and we are given the link of the website and also the source, and the hint that the flag is in /secret/flag.txt file path. 

First of all, let's explore the code and make a plan: we can see that there is only one method that unserializes an object, located in State.php called restore($token).

```php
    static function restore($token) {
        return unserialize(gzuncompress(base64_decode($token)));
    }
```

After that, we can notice that the only path we can see in all these files is the one representing the products' image: if we are able to modify this, we may obtain the flag as the image of one of the products. This is located in Products.php.

```php
function getPicture() {
        $path = '/var/www/assets/' . $this->picture;
        $data = base64_encode(file_get_contents($path));
        return $data;
    }

    function getPrice() {
        return $this->price;
    }

    function toDict() {
        return array(
            "id" => $this->id,
            "name" => $this->name,
            "description" => $this->description,
            "picture" => $this->getPicture(),
            "price" => $this->price
        );
    }
```

So: 
1. Start from the 

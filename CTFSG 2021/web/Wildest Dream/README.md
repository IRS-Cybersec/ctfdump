# Wildest Dream

### Miscellaneous [157] - 63 solves

______

**I am told that I can be in your [wildest dreams](http://chals.ctf.sg:30501/)...**

**Author: Gladiator**

Attached File: 1989.php

________

### Ok seriously there's a lot of Taylor Swift here

______

Going to the website, we are immediately greeted by someone's fantasy website of Taylor Swift.

![MAINPAGE](MAINPAGE.png)



Anyway this page is useless so we move on to `1989.php`.

![1989INITIAL](1989INITIAL.png)



Immediately we see more Taylor Swift (as expected from a fan site), but also the text `You need to provide two strings, i1 and i2. /1989.php?i1=a&i2=b`

Initial analysis of ONLY the PHP part of 1989.php yields:

```php
<?php
	if(!empty($_GET['i1']) && !empty($_GET['i2'])){
		$i1 = $_GET['i1'];
		$i2 = $_GET['i2'];
		if($i1 === $i2){
			die("i1 and i2 can't be the same!");
		}
		$len1 = strlen($i1);
		$len2 = strlen($i2);
		if($len1 < 20){
			die("i1 is too shorttttttt pee pee pee pee pee");
		}
		if($len2 < 20){
			die("i2 is too shorttttttt pee pee pee pee pee");
		}
		if(sha1(hex2bin($i1)) === sha1(hex2bin($i2)));
			if(md5(hex2bin($i1)) !== md5(hex2bin($i2)))
				echo "All I want to be is in your wildest dreams";
				if(md5(hex2bin($i1)) == md5(hex2bin($i2)))echo $flag;
		echo "<br>I think he did it, but i just cant prove it.";
	} else {
		echo "<br> You need to provide two strings, i1 and i2. /1989.php?i1=a&i2=b";
	}
															
?>
```

Reading the PHP carefully (and not glossing out that one trap), it requires the following conditions for the two inputs:

1.  `$i1` and `i2` must not be empty.
2. `$i1` and `$i2` must be 20 characters or more.
3. The `md5` sum of `hex2bin($i1)` must **strictly not** be equal to the `md5` sum of `hex2bin($i2)`
4. The `md5` sum of `hex2bin($i1)` has to be **loosely equal** to the `md5` sum of `hex2bin($i2)`

**Note that the `sha1` check from `if(sha1(hex2bin($i1)) === sha1(hex2bin($i2)));` is a red herring because of the semicolon attached to the back making it completely useless. The indentation made did stump the solve for quite awhile.** 

With that, solving the challenge is as easy as going to a well known GitHub repository of PHP magic hashes (https://github.com/spaze/hashes), finding two hashes with `0e` in front from the `md5` section (`abctvXqR55I` and `abcwmf8Vv7V`), converting it to hex and submitting the query string as:

` http://chals.ctf.sg:30501/1989.php?i1=6162637476587152353549&i2=616263776d663856763756`

The result is self-explanatory:

![1989FLAG](1989FLAG.png)



### Flag

_____

```
CTFSG{1-+h1nk-h3-d1d-1+-bu+-I-ju5t-c4n+-pr0v3-1t}
```


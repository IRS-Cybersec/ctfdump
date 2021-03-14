# Tangerine Stan [985 Points] - 8 Solves

```
I developed a super secure url parser. No way you can bypass it. But if you do, your bounty is in the Environment Variable!

Psst: It only accept links from tinyurl.com...

Author: Gladiator
http://chals.ctf.sg:30201/
```



## Initial Analysis

We are given the flask server's source code `server.py`

```python
from flask import Flask
from flask import request as flaskrequest
from urllib import request
from urllib.parse import urlparse

app = Flask(__name__)


@app.route('/search')
def hello():
    if flaskrequest.args['url'] == None:
        return "You need to access via /search?url=Your URL"
    url_proxy = flaskrequest.args['url']
    b = urlparse(url_proxy)
    print(b)
    print(url_proxy)
    if b.netloc != "tinyurl.com":
        return "URL is not from tinyurl.com"
    proxy_data = request.urlopen(url_proxy)
    safe_url = proxy_data.read().decode('utf-8') #Reads the tinyurl data (URL)
    safe_url_parsed = urlparse(safe_url)
    #if safe_url_parsed.scheme in ["file","gopher","ftp","smtp","tftp","mailto"]:
    #    return "Illegal Scheme Detected!"
    response = request.urlopen(safe_url)
    print(response)
    return response.read().decode('utf-8')

@app.route('/')
def main():
    return "Flag is in environment variable. <br>Please explore /search?url=[URL]"

if __name__ == '__main__':
    app.run(debug=True)
```

Some basic analysis of how it works:

- You must send a `tinyurl.com` like this `http://chals.ctf.sg:30201/search?url=tinyurl.com/sdads`, and it will **obtain the content** from the page that **`tinyurl` redirects to** (E.g if `tinyurl` redirects to `google.com.sg`, it will return the **html of the page**)
- This content is then parsed into a link, and its **scheme is checked against a list of blacklisted schemes**
  - If all is good, it will open the link and return the response

Hence, to redirect it to a URL we want, we can make `tinyurl.com` redirect to a pastebin/our own server with **raw contents containing another link**



## Initial (Failed) Attempts

We first tried to find some vulnerabilities in `urllib` that will hopefully allow us to trick `urlparse` into thinking that the `netloc` is `tinyurl.com` and the scheme is not `file://` when it actually is. But all the CVEs we reviewed were from 2019 and before. The organisers later confirmed that the `urllib` they were using is the very latest version, which effectively invalidates all these vulnerabilities.

We also looked into trying to achieve RCE, but this would require exploiting specific pre-existing programs on the device, which we have no information about. After the admins confirmed that we are not supposed to be finding a CVE, we can deduce that we are supposed to **read the environment variables** via files such as `/etc/profile`, `/etc/environment` or `/proc/self/environ`

We then looked into trying to achieve file read using an alternative protocol, but testing it out locally reveals that `urlopen` supports only a very small subset of schemes, such as `http`, `file` etc.



## The Solution

With the pathway of looking for an alternative scheme not going well. We decided to look back at somehow tricking `urllib`

In the final minutes of the competition, I randomly decided to add `<spaces>` around the url to see how `urlparse` will react to it. To my surprise, by adding a space in-front of the scheme, such as `<space>file:///etc/passwd`, `safe_url_parsed.scheme` actually **returns the space along with it**, which effectively **skips the illegal scheme check**.

Hence, we are free to use the `file://` protocol to obtain the environment variable files.

Our final payload was:

```
<space>file:///proc/self/environ
```

and the flag is:

```
CTFSG{I_Kept_This_Challenge_For_Three_Years_And_It_Is_Finally_Out_Long_Live_Gladiator}
```



------

## Learning Points

- This apparently is not the intended solution, but it's the most commonly used solution
- Environment variables can be **stored in files**
- Web is weird
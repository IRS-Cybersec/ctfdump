# Breaking Free
*Our agents managed to obtain the source code from the C2 server that COViD's bots used to register upon infecting its victim. Can you bypass the checks to retrieve more information from the C2 Server?*

*[C2 Server](http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41051/)* 

### Analysing the challenge
- This seems to be another API challenge where you will need to send malicious requests to the server.
- The source code of the server is as shown, as provided by the challenge:
```js
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const app = express();
const router = express.Router();
const COVID_SECRET = process.env.COVID_SECRET;
const COVID_BOT_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}$/g;
const Connection = require("./db-controller");
const dbController = new Connection();
const COVID_BACKEND = "web_challenge_5_dummy"

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

//Validates requests before we allow them to hit our endpoint
router.use("/register-covid-bot", (req, res, next) => {
  var invalidRequest = true;
  if (req.method === "GET") {
    if (req.query.COVID_SECRET && req.query.COVID_SECRET === COVID_SECRET) {
      invalidRequest = false;
    }
  } else {//Handle POST
    let covidBotID = req.headers['x-covid-bot']
    if (covidBotID && covidBotID.match(COVID_BOT_ID_REGEX)) {
      invalidRequest = false;
    }
  }

  if (invalidRequest) {
    res.status(404).send('Not found');
  } else {
    next();
  }

});

//registers UUID associated with covid bot to database
router.get("/register-covid-bot", (req, res) => {
  let { newID } = req.query;

  if (newID.match(COVID_BOT_ID_REGEX)) {
    //We enroll a maximum of 100 UUID at any time!!
    dbController.addBotID(newID).then(success => {
      res.send({
        "success": success
      });
    });
  }

});

//Change a known registered UUID
router.post("/register-covid-bot", (req, res) => {
  let payload = {
    url: COVID_BACKEND,
    oldBotID: req.headers['x-covid-bot'],
    ...req.body
  };
  if (payload.newBotID && payload.newBotID.match(COVID_BOT_ID_REGEX)) {
    dbController.changeBotID(payload.oldBotID, payload.newBotID).then(success => {
      if (success) {
        fetchResource(payload).then(httpResult => {
          res.send({ "success": success, "covid-bot-data": httpResult.data });
        })


      } else {
        res.send({ "success": success });
      }
    });
  } else {
    res.send({ "success": false });
  }

});

async function fetchResource(payload) {
  //TODO: fix dev routing at backend http://web_challenge_5_dummy/flag/42
  let result = await axios.get(`http://${payload.url}/${payload.newBotID}`).catch(err => { return { data: { "error": true } } });
  return result;
}

app.use("/", router);
```
- A simple look at the code tells us that the comments will come in handy later on in the challenge (the TODO).
- We see that there are 2 handlers for both a GET request and a POST request.
- There is a "security" middleware (a middleware is a function that requests have to pass through before it can continue to be processed) which checks for either the secret or a valid bot ID.

### Middleware Minecraft
- Looking at the style and pattern of the UUID, it is actually a v4 UUID (coincidentally it also resembles a Minecraft account UUID).
```js
const COVID_BOT_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}$/g;
// sample valid UUID: 747eb9e6-637b-4641-a058-835d5f7bbadc
```
- Since there will almost be no way to obtain the secret and we do not have any known bot IDs, we have to look into other ways to create our own bot ID.
- To create a bot ID, we have to get the request to be recognised as a GET request and pass the middleware secret too.
- Since the latter is highly impossible, we look into spoofing the request.
- Browsing the source code (or the [documentation](https://expressjs.com/en/api.html#router.METHOD) for those not well-versed with javascript), we find out this interesting line of code [over here](https://github.com/expressjs/express/blob/master/lib/router/route.js#L65).
- We also find a corresponding issue created at GitHub [here](https://github.com/expressjs/expressjs.com/issues/748).
- So all we need to do is to make a HEAD request to the server with our own bot ID as query and header (to pass middleware check)!
- Command: `$ curl -X HEAD "http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41051/register-covid-bot?newID=747eb9e6-637b-4641-a058-835d5f7bbadc" -H "x-covid-bot: 747eb9e6-637b-4641-a058-835d5f7bbadc"`
- The response will have a content length of 16, which presumably means `{"success":true}` and we are ready to do the next step!

### Dev for dummies
- We see that if we make a POST request to `/register-covid-bot` with our bot ID as payload, the server will make a backend request to the payload URL (`web_challenge_5_dummy`), and then proceed to output the response payload.
- The url is formed by concatenating the url and the bot ID: ```axios.get(`http://${payload.url}/${payload.newBotID}`)```
- So looking at that TODO comment line, we know that we simply have to make request to `web_challenge_5_dummy/flag/42`, but how do we do so with the extra bot ID at the back? 
- We will need to use the fragment sign `#` to append the bot ID as a fragment instead and won't be processed by the backend server.
- This can be possible as the developer used the spread operator for the request body, meaning that any request sent with additional keys will replace the existing keys, in which our case would be the `url` key of the payload object.
- Hence, we sent this command to the server with another UUID: `curl -X POST http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41051/register-covid-bot -H "x-covid-bot: 747eb9e6-637b-4641-a058-835d5f7bbadc" -H "Content-Type: application/json" -d '{"url":"web_challenge_5_dummy/flag/42#","newBotID":"2b08c880-f540-4485-975a-e935de95595c"}'`
- Response: `{"success":true,"covid-bot-data":{"flag":"govtech-csg{ReQu3$t_h34D_0R_G3T?}"}}`

### Flag! (Hurray!)
```govtech-csg{ReQu3$t_h34D_0R_G3T?}```

### Learning Outcomes
- Scrutinize the code provided carefully in web challenges, there are many hints and clues hidden in the challenge (such as using `req.method` to check the method type, and the TODO comment)
- This challenge also does require some knowledge on HTTP fragments, as using a GET query (`?`) will not work to hide the bot ID and solve the challenge.
- Some people might have thought that the `web_challenge_5_dummy` was not a valid host for the challenge, and instead went ahead to try to find the actual backend server, which was not intended by the challenge. Most server dynamic variables related to the challenge will be stored in the environment (e.g. `process.env`, the COVID_SECRET for example). Hence, there is no need to find the actual backend server url.

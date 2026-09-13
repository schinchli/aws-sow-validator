# Engineering notes

Concrete problems hit while building and deploying the AWS SOW Validator, written up as
symptom, root cause, and fix. Nothing here is hypothetical — every entry was reproduced
against a real deployed stack before being fixed.

## 1. CloudFront OAC + Lambda Function URL + `AWS_IAM` + a request body

**Symptom.** A `POST` to `/api/invoke` with a JSON body returned `403
InvalidSignatureException` from the Lambda origin. A `POST` with an empty body, or a plain
`GET`, worked fine. The failure was intermittent-looking in the sense that it depended
entirely on whether the caller happened to send a body — which made it easy to first suspect
CORS, then auth, before looking at signing.

**Root cause.** The Lambda Function URL is protected with `AuthType: AWS_IAM` and reached
only through CloudFront Origin Access Control (OAC) — there is no public, unauthenticated
Lambda endpoint anywhere in this architecture. CloudFront signs the forwarded request with
SigV4, but it does not compute a hash of the request body on the client's behalf. Per the
AWS documentation on [restricting access to a Lambda function URL
origin](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html):
"If you use PUT or POST methods with your Lambda function URL, your users must compute the
SHA256 of the body and include the payload hash value of the request body in the
`x-amz-content-sha256` header" — because Lambda does not accept unsigned payloads. Without
that header, CloudFront's own signature and the body no longer agree, and the origin rejects
the request as a signature mismatch, not a missing-header error, which is what made it
confusing to diagnose from the client side.

**Fix.** Hash the body in the browser before every `POST`, and hash the *exact* string being
sent — not a re-serialized version of the same object, which can differ in key order or
whitespace and produce a hash that doesn't match what actually goes over the wire:

```js
async function sha256Hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}

const bodyStr = JSON.stringify(body);
await fetch("/api/invoke", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-amz-content-sha256": await sha256Hex(bodyStr),
  },
  body: bodyStr,
});
```

## 2. AWS WAF CAPTCHA cannot be solved by `fetch()`

**Symptom.** A CAPTCHA rule action on `/api/*` broke the application's own front end in
production. Every call from the page's JavaScript to `/api/invoke` came back as an HTTP
challenge response — `x-amzn-waf-action: captcha` — instead of JSON, and `JSON.parse` threw
`Unexpected token '<'` because the body was an HTML challenge page, not the expected payload.

**Root cause.** [AWS WAF's CAPTCHA action](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html)
is designed to be solved by a human in a browser, either through the managed CAPTCHA UI or a
client-integration API — it has no code path that a plain `fetch()`/XHR call can satisfy.
Every programmatic call the app's own front end made to its own API was, from WAF's
perspective, indistinguishable from a bot, so it challenged all of them. Worse, the rule
protected nothing that needed it: every route under `/api/*` already requires a verified
Cognito ID token, checked inside the Lambda itself, and sign-up traffic goes directly to the
Cognito endpoint, never through CloudFront — so the CAPTCHA never even saw a sign-up attempt,
the traffic it might plausibly have been meant to gate.

**Fix.** Remove the CAPTCHA rule entirely. Keep the AWS Managed Rule Groups and a
rate-based rule (requests-per-IP over a rolling window) on the same paths — those inspect
without requiring an interactive challenge, so they don't collide with a JSON API. The web
CDK stack's test suite now asserts a CAPTCHA rule is absent, so a regression is a CI failure
rather than a repeat production incident.

## 3. CloudFront evaluates cache behaviors in list order, not by specificity

**Symptom.** A new `/api/*` wildcard behavior, added to handle a general-purpose route,
silently shadowed a more specific `/api/gmail/check` behavior that had been added earlier
to a different origin. Requests to the specific path started being served by the wrong
origin with the wrong access policy, with no error — just the wrong thing happening quietly.

**Root cause.** [CloudFront evaluates cache behaviors top-to-bottom and applies the *first*
path pattern that matches a request](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html) —
it does not re-sort by pattern specificity, and a broader pattern registered before a
narrower one will match first and the narrower one is never reached. In CDK, an
`additionalBehaviors` object's key insertion order becomes the synthesized template's
`CacheBehaviors` list order, so which behavior gets added to the object *first in code* is
what determines precedence at runtime — a detail that isn't visible from reading either
behavior definition in isolation.

**Fix.** Construct the specific behavior (`/api/gmail/check`) before the wildcard behavior
(`/api/*`) in the CDK code, so insertion order guarantees the specific match wins. The same
rule applies to `/share/*.json` versus `/share/*` in this stack — the exact-suffix behavior
has to be registered first or view-counted reads fall through to an uncounted, direct S3
fetch. Both orderings are called out with an explicit comment at the point of insertion, not
left to be re-discovered next time someone adds a route.

## 4. CLOUDFRONT-scope AWS WAF must live in `us-east-1`, no matter where the stack deploys

**Symptom.** Deploying the WAF web ACL in the same region as the rest of the stack (for
example `eu-west-1`) failed, or deployed a web ACL that CloudFront silently couldn't
associate with the distribution.

**Root cause.** [A web ACL for a CloudFront distribution must be created in the `us-east-1`
Region](https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html) —
this is a hard requirement of AWS WAF's CLOUDFRONT scope, not a default that happens to be
`us-east-1` and can be pointed elsewhere. Every other resource in this stack is free to
deploy anywhere Bedrock AgentCore is available; the WAF stack is the one exception, and a
naive "change the region and redeploy" fails on exactly this.

**Fix.** Split the WAF into its own CDK stack, hard-pinned to `us-east-1`:

```ts
const wafStack = new PocValidatorWafStack(app, 'PocValidatorWafStack', {
  env: { account, region: 'us-east-1' },
  crossRegionReferences: true,
});

new PocValidatorWebStack(app, 'PocValidatorWebStack', {
  env: { account, region },          // anywhere Bedrock AgentCore is available
  crossRegionReferences: true,
  webAclArn: wafStack.webAclArn,
});
```

`crossRegionReferences: true` lets the web stack consume the WAF stack's ARN output across
the region boundary, and CDK follows the resulting stack dependency automatically — running
`cdk deploy PocValidatorWebStack` alone still deploys the WAF stack first. It stays one
command even though it's two regions.

## 5. `CDK_DEFAULT_REGION` is set by the CDK CLI itself

**Symptom.** `export CDK_DEFAULT_REGION=eu-west-1 && cdk deploy` deployed to `us-east-1`
anyway, with no error and no indication the export was ignored.

**Root cause.** [`CDK_DEFAULT_REGION` and `CDK_DEFAULT_ACCOUNT` are environment variables
the CDK CLI itself injects into the app process](https://docs.aws.amazon.com/cdk/v2/guide/environments.html),
derived from the AWS SDK's own region resolution (the active profile, or `AWS_REGION` if
set) at the moment `cdk synth`/`cdk deploy` runs the app. Setting `CDK_DEFAULT_REGION`
directly in the shell doesn't change that resolution — the CLI overwrites it with its own
computed value before the app ever sees it, so the export has no effect regardless of what
value it was set to.

**Fix.** Set `AWS_REGION` instead. That's a real input to the SDK's region resolution, so
the CLI picks it up and *then* propagates it into `CDK_DEFAULT_REGION` for the app to read —
which is exactly the variable this stack's `bin/` entrypoint was already reading correctly.
The bug was never in the app code; it was in which environment variable to export.

```bash
AWS_REGION=eu-west-1 npx cdk deploy PocValidatorWebStack
```

## 6. `BucketDeployment` with `prune: false` leaves stale files served forever

**Symptom.** After a deploy that was meant to update the site's `index.html`, the browser
kept receiving an old version of the page at `/`. Nothing in the deploy logs indicated a
failure.

**Root cause.** The site's S3 bucket is not purely a static-asset bucket — the same Lambda
that serves the API also writes share-link JSON into it at runtime, as live user data. [CDK's
`BucketDeployment` prunes files from the destination that aren't in the deployment source by
default](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_s3_deployment.BucketDeployment.html);
turning that off (`prune: false`) is correct here — pruning would delete every share result a
user has ever generated on every deploy — but it has a side effect that's easy to miss: an
old `index.html` from a previous deploy, if it was ever left in place by any means other than
this deployment construct, is never cleaned up and keeps being served indefinitely.

**Fix.** With pruning off, the deployment must always write a real, current file over the
existing key rather than relying on deletion-then-recreate — `prune: false` is a permanent
constraint of this bucket's dual purpose, not a temporary workaround, so every deploy has to
actually overwrite `index.html` (and any other static page) explicitly rather than assume an
empty destination.

## 7. A missing `<meta charset="utf-8">` produces mojibake

**Symptom.** Certain characters in the static site (an em dash, a curly quote) rendered as
garbled multi-character sequences in some browsers, but not others, and not consistently.

**Root cause.** S3 and CloudFront serve static HTML with a `Content-Type: text/html`
response header that carries no `charset` parameter. Without an explicit charset — either
from the HTTP header or from a `<meta charset>` tag early in the document — some browsers
fall back to a legacy single-byte encoding (`windows-1252`) instead of UTF-8, and any
multi-byte UTF-8 character then decodes as multiple wrong characters. Separately, omitting
`<!doctype html>` at the very top of the document triggers "quirks mode" rendering in most
browsers, which affects layout and box-sizing behavior independently of the charset issue.

**Fix.** Put both at the very top of every HTML page, before anything else:

```html
<!doctype html>
<meta charset="utf-8">
```

Because the server-side `Content-Type` header can't easily carry a charset parameter from a
plain S3/CloudFront static-hosting setup, the `<meta charset>` tag is the reliable fix here,
not a server-side header change.

## 8. Email-domain allowlists must match exactly, not with `endswith`

**Symptom.** An allowlist meant to admit only `@amazon.com` addresses, implemented as
`email.endswith("amazon.com")`, would also admit `someone@amazon.com.evil.com` — a domain an
attacker fully controls, which merely happens to end in the allowed string.

**Root cause.** `endswith` matches a string suffix, not a domain component. A domain
allowlist has to compare the full domain segment after the `@`, not just check whether the
target string appears somewhere near the end. Equally important: this check has to run
server-side. A check implemented only in the browser is trivially bypassed by calling the
identity provider's sign-up API directly, skipping the page's JavaScript entirely.

**Fix.** Split the email into a local part and a domain with `rpartition("@")`, then compare
the domain for exact equality against each allowlist entry:

```python
_, _, email_domain = email.rpartition("@")
if email_domain == entry:   # exact match, not endswith
    return True
```

And enforce it in a [Cognito Pre sign-up Lambda
trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html),
which Cognito invokes on every self-service sign-up before the account is created — not in
client-side JavaScript, which only a well-behaved browser would ever run.

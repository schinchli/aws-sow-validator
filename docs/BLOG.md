# Stop guessing whether a POC architecture is sound: a deterministic reviewer built on Amazon Nova and Amazon Bedrock AgentCore

*An AWS Solutions Architect's build notes on the AWS SOW Validator, an open-source sample.*

## The problem AWS Partners actually have

Every AWS Partner doing pre-sales runs the same unglamorous loop. A customer sends an
architecture diagram and a Scope of Work (SOW). Someone senior reads both, decides whether
the design holds up, whether the SOW matches the design, and roughly what it will cost.
Then they do it again next week for a different customer, and the week after that for
another.

That review is where deals quietly go wrong. Two reviewers reach different verdicts on the
same diagram. A cost estimate is off because someone added up line items by hand at the end
of a long day. A service pair that does not actually integrate natively gets waved through
because it looked plausible. And when the customer asks three months later *why* something
was approved, nobody can reproduce the reasoning — the review lived in one person's head and
a marked-up PDF.

The obvious answer in 2026 is to hand the diagram and the SOW to a large language model and
ask "is this good?" That fails for a specific, structural reason: **you cannot put a number
a model invented in front of a customer.** A model that reads a diagram well will still,
occasionally, assert that two services integrate natively when they do not, or produce a
monthly total that is plausible and wrong. For a pre-sales artifact — the thing a customer
will hold you to — plausible-and-wrong is the worst possible failure mode. It doesn't look
like a bug. It looks like an answer.

The AWS SOW Validator is a sample built to solve this for AWS Partners and pre-sales teams,
behind a public web front end where a reviewer uploads a document and gets a structured
report back, without touching a terminal.

## The design rule: the model reads, Python decides

The whole system rests on one line, enforced rather than merely stated:

> **The model reads. Python decides.**

Amazon Nova handles what a model is genuinely good at — reading prose, extracting AWS
service names out of a document, banding vague SOW language onto a rubric ("does this
paragraph address backup and disaster recovery: not addressed, mentioned, partial, or
complete?"). Every number, every integration verdict, and every citation URL comes out of
deterministic Python running against versioned YAML rule packs — 20 cataloged AWS services,
46 verified integration pairs, 33 curated recommendation resources, spread across 7
rule-pack files (three industry packs, three segment packs, and a SOW-criteria pack). Submit
the same architecture three times and the findings, the integration verdicts, the cost
arithmetic, and every citation URL come back identical — $427.64 in three straight
production runs — because those parts of the answer never pass through a model at all.

The one number that does move is the model-assisted SOW score, and it's worth being precise
about why. Amazon Nova bands SOW prose onto the scoring rubric, and banding is not a
deterministic operation — the same three runs scored 75.0, 73.8, and 72.5. Treat that score
as advisory, the way you'd treat a colleague's gut-check rating: useful, informative, and
not a number you'd expect to reproduce bit-for-bit. Every figure a customer would actually
be held to — findings, integration verdicts, cost arithmetic, citation URLs — is not that
number, and is exactly reproducible.

This is not a stylistic preference. It is the difference between a tool a Partner
organization can stand behind and one it can only hope is right.

## Architecture: two tiers, one deterministic core

The system is two tiers sharing a single deterministic engine (`core/`), which imports
nothing AWS-specific and nothing model-specific — plain Python over YAML data files. That
independence is what lets the whole pipeline be exercised offline, with no AWS account, via
a CLI and a local UI, and it's what tests run against in about three seconds.

**Tier 1 — deterministic, no model, no Bedrock call.** Service detection by verbatim text
match with evidence snippets, rule-pack evaluation, integration chaining, pricing, and a
heuristic SOW score. This runs inside the web layer's Lambda in tens of milliseconds and
costs a fraction of a cent per review. It is the default path — the reason the tool is cheap
enough to expose publicly — and, because it never leaves the Lambda's own process, it is
roughly three orders of magnitude faster than the path that calls a model.

**Tier 2 — the Amazon Nova agent path.** For documents that genuinely need language
understanding rather than pattern matching — a hand-drawn diagram, SOW prose that has to be
judged rather than grepped — the request goes to an Amazon Bedrock AgentCore Runtime running
a five-phase agent: diagram intake, validation, pricing, SOW scoring, and recommendations.
Phases 2, 3, and 5 (validation, pricing, recommendations) never touch a model, even on the
Tier 2 path — only diagram reading and SOW-prose banding do.

A browser talks HTTPS to a single CloudFront distribution. The default behavior serves a
static upload page from S3; `/api/invoke` routes — via CloudFront Origin Access Control, so
the Lambda has no public URL of its own — to the Lambda that runs Tier 1 directly and brokers
Tier 2 calls to the AgentCore Runtime with `bedrock-agentcore:InvokeAgentRuntime`, an IAM
role scoped to exactly one runtime ARN.

## AWS services and what each one actually does

Not every AgentCore component fires on every review. CloudWatch logs from real production
runs show exactly two of them doing the work of a standard SOW analysis, and the rest
provisioned, reachable, and idle until a caller asks for what they do.

**Used in every review:**

| Service | Role in this system |
|---|---|
| **Amazon Bedrock** | Serves Amazon Nova, the model behind document extraction and SOW banding. |
| **Bedrock AgentCore Runtime** | Hosts the containerized five-phase agent. Serverless, billed per invocation, scales to zero. |

**Provisioned and reachable, but not invoked by a standard review — each has its own trigger:**

| Service | Trigger | Role in this system |
|---|---|---|
| **AgentCore Gateway** | The agent chooses to call it — zero calls in the production runs measured for this write-up | Exposes an AWS Documentation MCP server as a tool, so an "AWS recommends X" claim the agent grounds goes through a live documentation fetch rather than model memory. `gateway_available: true` in the response means reachable, not called — the recommendations phase answers deterministically without it. |
| **AgentCore Memory** | A caller supplies a stable identity across repeated sessions | Short-term summarization plus long-term semantic and user-preference recall across reviews. |
| **AgentCore Identity** | Only on the Gateway path | Mints the Gateway's OAuth token via an M2M flow — no client secret sits in an environment variable. |
| **AgentCore Policy Engine** | Enforces when a Gateway tool is called; idle when none are | Cedar policies in `ENFORCE` mode make read-only tool access a platform constraint, not a prompt instruction. |
| **AgentCore Code Interpreter** | An explicit what-if pricing question | Executes model-authored cost arithmetic in a managed sandbox and returns the executed code alongside the answer, so the result is auditable rather than asserted. |
| **Bedrock Knowledge Bases** | An explicit FAQ search | Vector search over a curated FAQ. Retrieval only — no generation call. |

**Always on, for the web layer:**

| Service | Role in this system |
|---|---|
| **Amazon CloudFront** | The single public entry point: one distribution, routed behaviors for the static site and the API. |
| **Amazon S3** | Static site hosting and the share-result cache, locked to CloudFront via Origin Access Control — the bucket itself is never public. |
| **AWS Lambda** | Runs Tier 1 in-process and brokers Tier 2 calls to the AgentCore Runtime. Has no public URL of its own. |
| **Amazon DynamoDB** | Atomic counters: per-user free-run quota, and the view-limited share-link cap, both enforced with conditional writes. |
| **Amazon Cognito** | Self-service sign-up with email verification, gated by a PreSignUp Lambda trigger. |
| **AWS WAF** | Managed rule groups and an IP rate-based rule on the API paths. |
| **AWS IAM** | Scopes every role to exactly what it needs — the web Lambda's execution role, the AgentCore Runtime's invocation role — nothing broader. |
| **Amazon CloudWatch** | Logs and metrics for the Lambda and the AgentCore Runtime, including OpenTelemetry-based traces from AgentCore's observability integration — this is the source for the "zero calls" figures above. |

## Where Amazon Nova fits, and why

Amazon Nova is the model layer for both entry points into the agent: the deployed runtime's
`AGENT_MODEL_ID` and `FAST_MODEL_ID` both point at `amazon.nova-pro-v1:0`. That is a
deliberate choice, not an incidental default.

The workload is high-volume, short-context, and structured: read a document, return a list
of AWS service names and a set of 0–4 band scores against a fixed rubric. It doesn't call
for frontier-scale reasoning; it calls for a model that's fast and inexpensive enough that a
reviewer will actually run it on every SOW that crosses their desk, not just the ones that
feel important enough to justify the wait. That's the whole rationale for the split
described above — Nova only ever has to be good at reading, because Python is where every
number and every verdict actually gets decided.

Two engineering notes from putting Nova into a Runtime loop that used tool calls, worth
passing on to anyone doing the same:

**Nova's tool-use streaming needs a fallback.** Under load, the Runtime occasionally emitted
`Model produced invalid sequence as part of ToolUse`, and in one case looped on the same tool
call until it hit the token ceiling. The fix isn't prompt engineering — it's a code path that
retries the same request without tools, asks for bare JSON instead, and extracts it from the
response. When that also fails, the request degrades to the deterministic Tier 1 result
rather than failing outright.

**Nova streams JSON objects, not only encoded strings.** The Server-Sent-Events reassembler
that unpacks the Runtime's response originally assumed every streamed chunk was a string and
crashed on a plain `"".join()` call, surfacing to the caller as an opaque 502. Worth checking
explicitly in any AgentCore integration that treats the response stream as "just strings."

Neither of these is a reason to avoid Nova — they're the ordinary cost of running any model
in production, and they're exactly why the determinism boundary below exists: when the model
misbehaves, the system returns a slightly less insightful answer, never a wrong number.

## The determinism boundary, enforced in code

Design rules that live only in a prompt are suggestions a model can quietly ignore under
pressure. These are enforced in code instead, and a test suite of 202 Python tests plus 34
CDK construct tests — running in a few seconds, with no network access — checks that they
stay enforced:

- An integration pair absent from the 46-pair catalogue is labelled **UNVERIFIED**, never
  silently approved. The classifier has no code path that lets it invent a verdict.
- Every recommendation URL is checked against an AWS-domain allowlist at import time, and a
  dedicated test asserts the rejection list is empty — a bad URL fails CI, not a customer
  demo.
- The model proposes band scores for the SOW rubric; Python computes the weighted total, and
  any total the model volunteers on its own is discarded outright.
- If the model call fails entirely — quota, access, a transient error — SOW scoring falls
  back to its deterministic heuristic floor, and the response says `model_assisted: false`
  rather than crashing the whole review.

The result is a system where the model can degrade the *quality* of an answer but never the
*correctness* of a number.

## Making it public without making it expensive

A validator nobody can reach is easy to secure. The moment it is public and every
agent review costs real Amazon Bedrock tokens, "who may use this, and how much"
becomes an architecture question rather than a policy one.

Four controls carry that weight, and none of them is a prompt instruction:

**Sign-up is an allowlist enforced in a Lambda, not in the browser.** A Cognito
PreSignUp trigger checks the address before an account is created. Enforcing it
client-side would be theatre — anyone can call the Cognito API directly and skip
the page entirely. The matching rule is worth stating because the obvious version
is a security bug:

```python
# Wrong: admits amazon.com.evil.com
email.endswith("amazon.com")

# Right: compare the domain, not the suffix
_, _, domain = email.lower().rpartition("@")
domain == "amazon.com"
```

Both `amazon.com.evil.com` and `sub.amazon.com` are rejected. The allowlist is an
environment variable, so a fork sets its own or disables it entirely.

**The expensive path is metered.** One free agent review per verified account, taken
with an atomic DynamoDB conditional update rather than a read-then-write. The
deterministic Tier-1 path stays unmetered, because it costs no model tokens at all.

**Uploads are capped and typed.** Word `.docx` only, up to 5 MB, enforced in the
Lambda and mirrored in the browser for fast feedback. The limit is published in the
page's runtime config so the UI shows the real server value instead of a string that
silently drifts out of date.

**AWS WAF sits at the edge** with the AWS managed common rule set, the IP reputation
list, and a rate-based rule. What it does *not* have is a CAPTCHA rule — see below.

## Four things that cost us an afternoon

**CloudFront OAC does not sign request bodies.** With a Lambda Function URL on
`AWS_IAM` auth behind Origin Access Control, a `POST` carrying any body returns
`403 InvalidSignatureException`. An empty body succeeds. The AWS documentation is
explicit: the client must compute the SHA-256 of the body and send it in
`x-amz-content-sha256`, because Lambda does not accept unsigned payloads. In the
browser that is four lines of `crypto.subtle.digest`, and the hash must cover the
exact string sent — serialise once, hash that variable, send that variable.

**AWS WAF CAPTCHA cannot be solved by `fetch()`.** A CAPTCHA action on `/api/*`
returned an HTML challenge page, so the front end's `JSON.parse` died on
`Unexpected token '<'`. It was also guarding nothing: those routes already require a
Cognito token, and sign-up traffic goes straight to Cognito without traversing
CloudFront. We removed it and kept a test asserting it stays removed. CAPTCHA is
still a sensible control — for unauthenticated, browser-rendered forms, not for an
XHR-driven JSON API.

**CloudFront evaluates cache behaviors in list order, not by specificity.** A new
`/api/*` wildcard silently shadowed a more specific `/api/gmail/check` added later
via `addBehavior()`. The fix is construction order, not path precision.

**Graphviz writes icon paths absolutely.** The generated SVG referenced
`/private/tmp/.../site-packages/resources/aws/security/waf.png` — every AWS icon
vanished when the file was served from S3 or rendered on GitHub. The generator now
base64-inlines each icon as a data URI and fails loudly if one is missing, rather
than shipping a blank diagram.

None of these appear in a tutorial. All four are the difference between an
architecture that looks right and one that runs.

## What it found on a real Scope of Work

The numbers below are from one run against a genuine partner SOW — a Bedrock
inference migration — on Amazon Bedrock AgentCore Runtime. Nothing is
illustrative.

**Extraction.** 100% of content parts: the body, 9 tables (47 rows, 153 cells),
five footers, footnotes, document properties, and 11 embedded images. Coverage is
reported per part, and anything unreadable is listed with a reason rather than
dropped silently.

**Diagram.** Identified automatically, and this took three attempts to get right.
"Largest raster image" picks a full-bleed cover graphic almost every time — on
this document a 1.2 MB gradient beat the 322 KB architecture diagram, and the
review then ran against the gradient while reporting success. Selection now
resolves in order: proximity to architecture wording, then a vision pass that
looks *inside* candidate images for AWS service icons, then size as a last
resort. Whichever rule fired is recorded, so the choice is auditable. When the
vision pass finds no AWS icons anywhere, the extractor returns **no diagram** —
many SOWs genuinely have none, and handing the phase a gradient invites a
hallucinated reading.

**The finding that justifies the whole exercise.** The document states
**$10,501.18/month**. The independent estimate came to **$248.47**. A 42x
divergence, previously reported as nothing at all. Cost reconciliation now raises
it as High, and a companion finding names exactly what could not be priced —
SageMaker and two Claude Opus models the catalogue has no rate for — so a
reviewer sees *why* the gap exists instead of guessing.

**A false High, removed.** The rule packs had flagged "private subnet not enabled
on Amazon EC2". The architecture contains no EC2. The word appeared once, in the
out-of-scope section: *"operation of custom or open-weight models on Amazon
SageMaker or Amazon EC2"*. Detection had no notion of negation, so an explicit
exclusion became an in-scope service — and carried $179 of phantom cost, 42% of
the estimate. Detection is now negation-aware: a service named only inside an
exclusion region is not in scope, and is not priced.

## What the optimisation was worth

The model layer was rewritten after measuring where the tokens went:

| | Before | After |
|---|---|---|
| Full-document passes per review | ~15 | 1 |
| Input tokens | ~98,000 | ~1,600 |
| Latency | 20.9s | 5-7s |
| Failed tool calls | 14 | 0 |

Nova reliably fails a JSON-array tool schema and reliably succeeds with bare
JSON, so the fallback became the primary path. Only criteria the deterministic
heuristic is unsure about are sent, each with its own evidence window rather than
the whole document. Findings and cost totals were byte-identical before and
after — the optimisation cut cost, not accuracy.

## Where it is honest about its limits

Service coverage is bounded by the catalogue. On this SOW, KMS, CloudTrail and
PrivateLink appeared in the prose, the diagram *and* the priced line items, and
were invisible to the rule packs until they were added. The tool now detects
services from three independent sources — narrative, cost table, and the icons
visible in the diagram — which is what makes "priced but not drawn" and "drawn
but not scoped" detectable at all.

## Deploy it in your own account

The base install needs no Bedrock access and no container build — the Amazon Nova agent path
is opt-in, added on top of a working deterministic instance:

```bash
git clone https://github.com/schinchli/aws-sow-validator
cd aws-sow-validator/infrastructure/cdk
npm ci
npx cdk deploy PocValidatorWebStack
```

That single command produces CloudFront, S3, a Lambda running the deterministic Tier 1
engine, DynamoDB, a Cognito user pool with self-service sign-up, and AWS WAF. Every CDK
context value is optional; a bare deploy is a working public instance.

To add the Amazon Nova agent path, deploy the AgentCore application separately and pass its
runtime ARN back into the web stack:

```bash
agentcore deploy                     # builds the container, creates Runtime/Memory/Gateway
npx cdk deploy PocValidatorWebStack -c agentRuntimeArn=<arn>
```

Without that context value the stack still deploys cleanly and the UI simply hides the
agent-review button. Splitting it this way — cheap and always-on versus expensive,
permission-heavy, and opt-in — is deliberate: nobody should have to request Bedrock model
access just to try the deterministic core. See the [Amazon Bedrock model access
documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html) for
enabling Nova in your own account before deploying the agent path.

## Region portability

The stack is designed to move: `AWS_REGION=<region> npx cdk deploy PocValidatorWebStack`
redeploys the whole thing anywhere Amazon Bedrock AgentCore and the model it calls are both
available. As of this writing, that's confirmed — by direct API probe, not documentation
alone — in `us-east-1`, `us-west-2`, `ap-south-1`, `ap-southeast-2`, `eu-central-1`,
`eu-west-1`, and `ap-northeast-1`.

One constraint doesn't move with the rest of the stack: [AWS WAF for a CloudFront
distribution must be created in `us-east-1`](https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html),
regardless of where everything else lives. This sample handles that with a second stack
pinned to `us-east-1` and consumed across the region boundary with `crossRegionReferences`,
so `cdk deploy` still deploys both halves as one command — see [docs/LESSONS.md](LESSONS.md)
for the exact CDK shape and a second, easy-to-miss gotcha in the same area:
`CDK_DEFAULT_REGION` is set by the CDK CLI itself from your profile at synth time, so
exporting it yourself has no effect — [`AWS_REGION` is the variable that actually changes
anything](https://docs.aws.amazon.com/cdk/v2/guide/environments.html).

## Cost, by shape

Nothing in this system runs continuously, so the honest way to describe cost is by shape,
not by quoting a rate that will be stale by the time you read it — check the [Amazon Bedrock
pricing page](https://aws.amazon.com/bedrock/pricing/) and the [AWS WAF pricing
page](https://aws.amazon.com/waf/pricing/) for current figures and build your own estimate
from there.

- **Tier 1, the deterministic review**, costs a fraction of a cent — it's Lambda
  milliseconds with no model call involved at all.
- **Tier 2, the Amazon Nova agent review**, costs cents per review — the AgentCore Runtime
  and Bedrock both bill per invocation, with no idle charge between reviews.
- **AWS WAF is the one meaningful fixed monthly cost** in the whole stack — a web ACL and
  its rules bill by the month regardless of traffic.
- **Everything else — CloudFront, S3, Lambda, DynamoDB, Cognito** — scales to zero. There's
  no NAT gateway, no provisioned concurrency, no always-on compute, and no search cluster
  sitting idle waiting for the next review.

That shape is what makes a public demo instance tolerable to run: idle cost is close to
zero, and the number that does grow (Tier 2 usage) grows in cents, not dollars, per review.

## Cleaning up

Everything is destroyable in one command per region, dry run by default:

```bash
./scripts/teardown_all.sh us-east-1              # show what would be deleted
./scripts/teardown_all.sh us-east-1 --confirm    # delete, after typing the region back
```

It removes the web stack, the agent stack, and the separate `us-east-1` WAF stack, then lists
the S3 buckets and ECR repositories that CloudFormation retains when they're non-empty — with
the commands to remove those too. Retained, non-empty buckets and image repositories are the
usual reason a "deleted" stack keeps quietly costing money; this sample surfaces them instead
of leaving you to discover it on next month's bill.

---

The bugs that shaped several of the decisions above — the exact `403` a signed Lambda
Function URL returns when a POST body isn't hashed, why a CAPTCHA action can break your own
API, why CloudFront's cache-behavior order isn't sorted by specificity — are written up as
concrete, standalone symptom-cause-fix notes in [docs/LESSONS.md](LESSONS.md).

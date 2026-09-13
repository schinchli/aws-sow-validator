import * as path from 'path';
import { CfnOutput, Duration, RemovalPolicy, Stack, StackProps, Tags } from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import * as ses from 'aws-cdk-lib/aws-ses';
import * as sesActions from 'aws-cdk-lib/aws-ses-actions';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';

// This project's own sign-up allowlist: any *@amazon.com address, plus one
// personal address. A fork should pass its own `signupAllowed` context
// value (see bin/web.ts) — or the empty string to allow open sign-up —
// rather than editing this default. See source/api/allowlist.py for the
// exact matching rule (domain entries match exactly; no subdomains).
const DEFAULT_SIGNUP_ALLOWED = 'amazon.com,schinchli@gmail.com';

// Server-side cap (bytes) on the combined sow_text + diagram_text payload —
// see maxUploadBytes prop doc comment. Must match source/api/handler.py's
// own MAX_UPLOAD_BYTES default so a stack deployed without the context value
// and a Lambda invoked without the env var agree on the same number.
const DEFAULT_MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB

export interface PocValidatorWebStackProps extends StackProps {
  /**
   * OPTIONAL: ARN of an already-deployed AgentCore Runtime (managed by
   * agentcore/cdk, not this stack). Unset makes the agent/Nova review path
   * unavailable — mode="agent" answers a clean 503 — while the Tier 1
   * deterministic engine (no model, no Bedrock access needed) stays fully
   * functional. This is what makes a one-command deploy into a fresh
   * account realistic: no container build, no Bedrock access required for
   * the base install.
   */
  readonly agentRuntimeArn?: string;
  /**
   * OPTIONAL: Basic-Auth credential the CloudFront Function checks against,
   * as "user:pass" base64. Only meaningful for the owner-only
   * /api/gmail/check route (see gmailSecretArn/gmailOwner below) — the rest
   * of the site is public self-service. Leaving this unset when Gmail is
   * configured deploys /api/gmail/check without edge auth; set it to
   * protect that one route.
   */
  readonly basicAuthCredentialBase64?: string;
  /** OPTIONAL: vestigial Basic-Auth-era shared secret, still read by the
   *  Lambda (DEMO_KEY) but no longer used to gate any route — Cognito JWT +
   *  quota is the real access control. Defaults to a placeholder so no
   *  manual value is required for a fresh deploy. */
  readonly demoKey?: string;
  /** OPTIONAL: cross-region ARN of the CLOUDFRONT-scope WAFv2 Web ACL
   *  (from PocValidatorWafStack, which must live in us-east-1 — see
   *  infrastructure/cdk/lib/waf-stack.ts and bin/web.ts). Unset deploys the
   *  distribution without a WAF attached rather than failing the whole
   *  stack — useful for a quick first deploy or a region where the WAF
   *  stack hasn't been deployed yet. */
  readonly webAclArn?: string;
  /** OPTIONAL: hosted-agent-review free quota per verified user. Default 1. */
  readonly freeRuns?: number;
  /** OPTIONAL: server-side cap, in bytes, on the combined sow_text +
   *  diagram_text payload accepted by /api/invoke. Defaults to 5 MB
   *  (5242880). Also published to the front end via config/auth.json so the
   *  page can display/enforce the real limit instead of a hardcoded one. */
  readonly maxUploadBytes?: number;
  /** OPTIONAL: where a user who has exhausted their free quota is pointed to
   *  self-host instead of asking for more runs. Defaults to this project's
   *  own repo. */
  readonly selfHostUrl?: string;
  /** OPTIONAL: Secrets Manager ARN of a Google service-account key JSON. Both
   *  drive* props empty leaves the /api/drive routes cleanly unconfigured. */
  readonly driveSaSecretArn?: string;
  /** OPTIONAL: the Google Drive folder id the service account may read. */
  readonly driveFolderId?: string;
  /** OPTIONAL: domain for email-in SOW reviews (e.g. "review.example.com").
   *  Unset leaves the email pipeline entirely out of the stack. The domain's
   *  DNS needs the MX + DKIM records this stack outputs after deploy. */
  readonly emailDomain?: string;
  /** OPTIONAL: comma-separated senders allowed to use the email pipeline.
   *  Anyone else's mail is dropped silently. */
  readonly emailAllowedSenders?: string;
  /** OPTIONAL: Secrets Manager ARN of the Gmail OAuth credentials JSON
   *  ({client_id, client_secret, refresh_token}). Set to enable the
   *  AWS-native Gmail poller (email-in reviews + email chat on the owner's
   *  own mailbox, no domain or DNS needed). */
  readonly gmailSecretArn?: string;
  /** OPTIONAL: the mailbox owner (only sender the poller reacts to). */
  readonly gmailOwner?: string;
  /** OPTIONAL: comma-separated email allowlist enforced at sign-up (Cognito
   *  PreSignUp trigger, source/api/presignup.py) and again on every API call
   *  as defence in depth (source/api/handler.py). An entry containing "@" is
   *  an exact address match; an entry without "@" is a domain match (exact —
   *  no subdomains, no lookalikes). Defaults to this project's own
   *  allowlist (`*@amazon.com` + one personal address); a fork should pass
   *  its own value, or the empty string to allow open sign-up. See
   *  source/api/allowlist.py for the matching rule. */
  readonly signupAllowed?: string;
  /**
   * The distribution's own public URL (e.g. "https://d1234.cloudfront.net"),
   * needed by the Lambda for CORS and for building share_url links back to
   * itself. Unknowable on a true first deploy — leave undefined, deploy once,
   * read the DistributionDomainName output, then redeploy passing it. This
   * two-phase dance is inherent to any CloudFront-fronts-its-own-Lambda
   * setup; trying to wire it as a same-stack reference creates a circular
   * CloudFormation dependency (Distribution needs the Function URL as an
   * origin; Lambda would need the Distribution's domain name).
   */
  readonly publicBaseUrl?: string;
}

/**
 * The web layer in front of the poc-validator-agent AgentCore Runtime:
 * a static page (S3 + CloudFront), a Lambda proxy for running the agent and
 * serving view-limited shared results, and the DynamoDB table backing the
 * 3-view / 30-day share cap.
 *
 * This stack defines every resource as CDK would create it fresh. The
 * equivalent resources already exist by hand in the account (built
 * incrementally, verified at each step) — see infrastructure/cdk/README.md for the
 * `cdk import` path to adopt them instead of standing up duplicates.
 */
export class PocValidatorWebStack extends Stack {
  constructor(scope: Construct, id: string, props: PocValidatorWebStackProps) {
    super(scope, id, props);

    // ---- Storage: the static page/share-shell bucket ----------------------
    const siteBucket = new s3.Bucket(this, 'SiteBucket', {
      bucketName: `poc-validator-agentcore-demo-${this.account}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          id: 'expire-shared-results-30d',
          enabled: true,
          prefix: 'share/',
          tagFilters: { AutoExpire: 'true' },
          expiration: Duration.days(30),
        },
        {
          // Review-response cache: identical inputs are served from here at
          // zero model cost. 7 days keeps repeat validations instant while
          // guaranteeing rule-pack updates surface within a week.
          id: 'expire-review-cache-7d',
          enabled: true,
          prefix: 'cache/',
          expiration: Duration.days(7),
        },
      ],
    });

    // ---- View-count table for the 3-view share cap -------------------------
    const viewsTable = new dynamodb.Table(this, 'ShareViewsTable', {
      tableName: 'poc-validator-share-views',
      partitionKey: { name: 'share_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ---- End-user identity: self-service Cognito user pool ----------------
    // Distinct from the pre-existing M2M "PocValidator-UserPool" (client
    // credentials, service-to-service) — this pool is for real people
    // signing up in the browser. Torn down with the rest of this stack.
    const userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'poc-validator-end-users',
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      autoVerify: { email: true },
      userVerification: {
        emailStyle: cognito.VerificationEmailStyle.CODE,
      },
      standardAttributes: {
        email: { required: true, mutable: false },
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: false,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Public client (no secret) — the browser calls the Cognito REST API
    // (InitiateAuth) directly with fetch, so only USER_PASSWORD_AUTH is
    // needed; CDK always adds ALLOW_REFRESH_TOKEN_AUTH regardless of the
    // authFlows given here.
    const userPoolClient = userPool.addClient('UserPoolClient', {
      userPoolClientName: 'poc-validator-web-client',
      generateSecret: false,
      authFlows: {
        userPassword: true,
        userSrp: false,
      },
      preventUserExistenceErrors: true,
    });

    // ---- UsersTable: FREE_RUNS quota for the free/self-service tier -------
    // No purchasable-credits concept: past FREE_RUNS the answer is "deploy
    // your own copy" (see source/api/handler.py SELF_HOST_URL), not "buy more".
    const usersTable = new dynamodb.Table(this, 'UsersTable', {
      tableName: 'poc-validator-users',
      partitionKey: { name: 'user_sub', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // ---- Lambda: invokes the agent, serves view-limited share reads -------
    // Shared by the web-invoke and email-review functions: one bundle
    // carrying handler.py, tier1.py, email_review.py, pocvalidator/core
    // and the config/data/ catalogue.
    const bundledCode = lambda.Code.fromAsset(path.join(__dirname, '..', '..', '..', '..', 'source', 'api'), {
        bundling: {
          // Prefer a plain host `pip install` (same command used to build the
          // real, deployed package by hand) over Docker-based bundling — the
          // Docker image pull for lambda.Runtime bundlingImage has been a
          // real source of friction/hangs on this machine. Docker bundling
          // is kept as the fallback for a CI/fresh-machine deploy where the
          // host may not have a matching Python available.
          image: lambda.Runtime.PYTHON_3_13.bundlingImage,
          // NOTE: the Docker fallback cannot reach pocvalidator/core or
          // config/data/ (they live outside the asset dir) — a Docker-bundled
          // deploy ships agent-only and Tier 1 answers 503. The local bundler
          // below is the real deploy path and bundles everything.
          command: ['bash', '-c', 'pip install -r requirements.txt -t /asset-output && cp handler.py tier1.py email_review.py gmail_poller.py sse.py allowlist.py presignup.py /asset-output/'],
          local: {
            tryBundle(outputDir: string): boolean {
              const { execFileSync } = require('child_process');
              const src = path.join(__dirname, '..', '..', '..', '..', 'source', 'api');
              // __dirname is infrastructure/cdk/dist/lib at synth time (cdk.json runs the
              // compiled dist/), so up 4 levels lands on the repo root (holding
              // source/ and config/), from which src and repoRoot below are derived.
              const repoRoot = path.join(__dirname, '..', '..', '..', '..');
              try {
                // Target Lambda's platform explicitly: google-auth pulls the
                // native `cryptography` wheel, and a host-platform (macOS)
                // build would crash at import inside the x86_64 runtime.
                execFileSync('pip3', [
                  'install', '--quiet',
                  '--platform', 'manylinux2014_x86_64',
                  '--implementation', 'cp',
                  '--python-version', '3.13',
                  '--only-binary', ':all:',
                  '-r', path.join(src, 'requirements.txt'),
                  '-t', outputDir,
                ]);
                execFileSync('cp', [
                  path.join(src, 'handler.py'), path.join(src, 'tier1.py'),
                  path.join(src, 'email_review.py'), path.join(src, 'gmail_poller.py'),
                  path.join(src, 'sse.py'), path.join(src, 'allowlist.py'),
                  path.join(src, 'presignup.py'), outputDir,
                ]);
                // Tier 1's deterministic engine: the core package (as the
                // pocvalidator namespace package) plus its YAML catalogue.
                // POCVALIDATOR_ROOT is set to /var/task below, and catalog.py
                // resolves DATA/RULES at <root>/config/data and
                // <root>/config/rules, so the catalogue must land at
                // config/data under the asset root, mirroring the on-disk
                // layout rather than special-casing catalog.py for Lambda.
                execFileSync('mkdir', ['-p', path.join(outputDir, 'pocvalidator')]);
                execFileSync('cp', ['-r', path.join(repoRoot, 'source', 'agent', 'core'), path.join(outputDir, 'pocvalidator', 'core')]);
                execFileSync('mkdir', ['-p', path.join(outputDir, 'config')]);
                execFileSync('cp', ['-r', path.join(repoRoot, 'config', 'data'), path.join(outputDir, 'config', 'data')]);
                // RULES resolves to <root>/config/rules in catalog.py. Omitting
                // this ships a Lambda whose rule packs are missing, which fails
                // only at runtime with every review returning nothing.
                execFileSync('cp', ['-r', path.join(repoRoot, 'config', 'rules'), path.join(outputDir, 'config', 'rules')]);
                return true;
              } catch (err) {
                // Never swallow this silently: the Docker fallback needs a
                // running daemon, so a hidden local failure becomes an
                // inscrutable synth with no assembly at all.
                console.error('[bundling] local bundler failed, falling back to Docker:', err);
                return false;
              }
            },
          },
        },
      });

    // ---- Cognito PreSignUp trigger: the authoritative sign-up allowlist ---
    // Enforced here, not just client-side, because a browser-side check is
    // trivially bypassed by calling the Cognito SignUp API directly. See
    // source/api/presignup.py + source/api/allowlist.py for the matching
    // rule; webInvokeFn below re-checks the same allowlist as defence in
    // depth. Deliberately does NOT auto-confirm the user or auto-verify
    // their email — the normal verify-by-code flow still applies to allowed
    // addresses.
    const presignupFn = new lambda.Function(this, 'PreSignUpFunction', {
      functionName: 'poc-validator-presignup',
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'presignup.handler',
      code: bundledCode,
      timeout: Duration.seconds(10),
      memorySize: 128,
      environment: {
        SIGNUP_ALLOWED: props.signupAllowed ?? DEFAULT_SIGNUP_ALLOWED,
        SELF_HOST_URL: props.selfHostUrl ?? 'https://github.com/awslabs/agentcore-samples',
      },
    });
    // Wires the Lambda as the pool's PRE_SIGN_UP trigger (and grants Cognito
    // invoke permission on it) — every SignUp/AdminCreateUser call runs
    // through presignupFn before an account is created.
    userPool.addTrigger(cognito.UserPoolOperation.PRE_SIGN_UP, presignupFn);

    const webInvokeFn = new lambda.Function(this, 'WebInvokeFunction', {
      functionName: 'poc-validator-web-invoke',
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'handler.handler',
      // Ships its own boto3/botocore rather than relying on the runtime's
      // bundled version, which may predate the bedrock-agentcore service.
      code: bundledCode,
      timeout: Duration.minutes(5),
      memorySize: 512,
      environment: {
        // Empty means no AgentCore runtime configured for this deployment —
        // see agentRuntimeArn doc comment. The Lambda treats this as
        // "agent mode unavailable, deterministic mode still works".
        AGENT_RUNTIME_ARN: props.agentRuntimeArn ?? '',
        DEMO_KEY: props.demoKey ?? 'unused-vestigial-key',
        RESULTS_BUCKET: siteBucket.bucketName,
        VIEWS_TABLE: viewsTable.tableName,
        // See publicBaseUrl doc comment: unknowable on a first deploy without
        // creating a circular dependency on the Distribution below.
        ALLOWED_ORIGIN: props.publicBaseUrl ?? '*',
        PUBLIC_BASE_URL: props.publicBaseUrl ?? '',
        DRIVE_SA_SECRET_ARN: props.driveSaSecretArn ?? '',
        DRIVE_FOLDER_ID: props.driveFolderId ?? '',
        // Points the bundled pocvalidator.core catalogue loader at the
        // data/ directory the local bundler copies into the asset root.
        POCVALIDATOR_ROOT: '/var/task',
        // End-user auth (Cognito ID token verification) + quota tracking.
        USER_POOL_ID: userPool.userPoolId,
        USER_POOL_CLIENT_ID: userPoolClient.userPoolClientId,
        USERS_TABLE: usersTable.tableName,
        FREE_RUNS: String(props.freeRuns ?? 1),
        SELF_HOST_URL: props.selfHostUrl ?? 'https://github.com/awslabs/agentcore-samples',
        // Defence-in-depth allowlist check on every API call — see
        // signupAllowed's prop doc comment and source/api/allowlist.py.
        SIGNUP_ALLOWED: props.signupAllowed ?? DEFAULT_SIGNUP_ALLOWED,
        // See maxUploadBytes prop doc comment and handler.py's MAX_DOCUMENT_BYTES.
        MAX_UPLOAD_BYTES: String(props.maxUploadBytes ?? DEFAULT_MAX_UPLOAD_BYTES),
      },
    });

    // Deliberately explicit rather than the L2 grant*() convenience methods:
    // those grant broader action sets (List*, DeleteItem, Scan, Query, ...)
    // than this Lambda ever calls. This lists exactly the actions verified
    // against the live, hand-built role — matching the real security
    // posture is worth more here than the convenience.
    // Only meaningful (and only synthesizable — an ARN string is required)
    // when an AgentCore runtime is actually configured; see agentRuntimeArn.
    if (props.agentRuntimeArn) {
      webInvokeFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['bedrock-agentcore:InvokeAgentRuntime'],
          resources: [props.agentRuntimeArn, `${props.agentRuntimeArn}/runtime-endpoint/*`],
        })
      );
    }
    webInvokeFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:PutObject', 's3:PutObjectTagging', 's3:GetObject'],
        resources: [siteBucket.arnForObjects('share/*'), siteBucket.arnForObjects('cache/*')],
      })
    );
    webInvokeFn.addToRolePolicy(
      new iam.PolicyStatement({
        // Tier 1's brand-contamination check reads the confidential
        // banned-brand list uploaded out-of-band to config/ (never committed).
        actions: ['s3:GetObject'],
        resources: [siteBucket.arnForObjects('config/banned-clients.json')],
      })
    );
    webInvokeFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:GetItem'],
        resources: [viewsTable.tableArn],
      })
    );
    webInvokeFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
        resources: [usersTable.tableArn],
      })
    );
    if (props.driveSaSecretArn) {
      webInvokeFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['secretsmanager:GetSecretValue'],
          resources: [props.driveSaSecretArn],
        })
      );
    }

    const webInvokeFnUrl = webInvokeFn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.AWS_IAM,
      cors: {
        allowedOrigins: ['*'], // effectively same-origin once behind CloudFront; not the real gate
        allowedMethods: [lambda.HttpMethod.GET, lambda.HttpMethod.POST],
        allowedHeaders: ['content-type', 'x-demo-key', 'authorization'],
      },
    });

    // ---- Basic Auth at the edge (owner-only /api/gmail/check only) --------
    // Public self-service everywhere else — this Function only ever gets
    // attached to the Gmail-check behavior further down, and only when a
    // credential is actually supplied.
    const basicAuthFn = props.basicAuthCredentialBase64
      ? new cloudfront.Function(this, 'BasicAuthFunction', {
          functionName: 'poc-validator-basic-auth',
          runtime: cloudfront.FunctionRuntime.JS_2_0,
          code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
    var request = event.request;
    var headers = request.headers;
    var expected = "Basic ${props.basicAuthCredentialBase64}";
    if (!headers.authorization || headers.authorization.value !== expected) {
        return {
            statusCode: 401,
            statusDescription: "Unauthorized",
            headers: { "www-authenticate": { value: 'Basic realm="POC Validator demo"' } },
        };
    }
    delete headers.authorization;
    return request;
}
`),
        })
      : undefined;

    // ---- OPTIONAL: AWS-native Gmail poller (function only) -----------------
    // Defined here — before the Distribution below — purely so its
    // CloudFront behavior can be inserted into additionalBehaviors ahead of
    // the /api/* wildcard (see the comment on additionalBehaviors just below
    // for why that ordering is load-bearing). Everything that needs the
    // Distribution itself (the CloudFront-invoke permission, the CfnOutputs)
    // stays in the original spot further down, after it's created.
    let pollerFn: lambda.Function | undefined;
    let pollerFnUrl: lambda.FunctionUrl | undefined;
    if (props.gmailSecretArn && props.gmailOwner) {
      pollerFn = new lambda.Function(this, 'GmailPollerFunction', {
        functionName: 'poc-validator-gmail-poller',
        runtime: lambda.Runtime.PYTHON_3_13,
        handler: 'gmail_poller.handler',
        code: bundledCode,
        timeout: Duration.minutes(3),
        memorySize: 512,
        environment: {
          GMAIL_SECRET_ARN: props.gmailSecretArn,
          OWNER_EMAIL: props.gmailOwner,
          ALIAS_EMAIL: props.gmailOwner.replace('@', '+sow@'),
          CONFIG_BUCKET: siteBucket.bucketName,
          // Empty means email chat follow-ups (which need the runtime) are
          // unavailable; the initial deterministic review still works.
          AGENT_RUNTIME_ARN: props.agentRuntimeArn ?? '',
          POCVALIDATOR_ROOT: '/var/task',
        },
      });
      pollerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['secretsmanager:GetSecretValue'],
          resources: [props.gmailSecretArn],
        })
      );
      pollerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['s3:GetObject', 's3:PutObject'],
          resources: [siteBucket.arnForObjects('gmail-state/*')],
        })
      );
      pollerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [siteBucket.arnForObjects('config/banned-clients.json')],
        })
      );
      if (props.agentRuntimeArn) {
        pollerFn.addToRolePolicy(
          new iam.PolicyStatement({
            actions: ['bedrock-agentcore:InvokeAgentRuntime'],
            resources: [props.agentRuntimeArn, `${props.agentRuntimeArn}/runtime-endpoint/*`],
          })
        );
      }
      // Event-driven, no schedules: the owner pings GET /api/gmail/check
      // (bookmark on the phone, behind the same Basic Auth) right after
      // sending the email, and the mailbox is processed that instant.
      // Nothing runs — and nothing is billed — between pings.
      pollerFnUrl = pollerFn.addFunctionUrl({
        authType: lambda.FunctionUrlAuthType.AWS_IAM,
        cors: {
          allowedOrigins: [props.publicBaseUrl ?? '*'],
          allowedMethods: [lambda.HttpMethod.GET],
        },
      });
    }

    // ---- CloudFront: one distribution, two origins, ordered routes --------
    const s3Origin = origins.S3BucketOrigin.withOriginAccessControl(siteBucket);
    const lambdaOrigin = origins.FunctionUrlOrigin.withOriginAccessControl(webInvokeFnUrl);

    // Order matters: CDK preserves this object's key insertion order in the
    // synthesized template's CacheBehaviors list, and CloudFront evaluates
    // that list top-to-bottom, using the FIRST path pattern that matches a
    // request — it does not re-sort by specificity. So:
    //   - /api/gmail/check (the owner-only, Basic-Auth-gated route) MUST be
    //     inserted ahead of the /api/* wildcard below, or the wildcard would
    //     shadow it — matching every /api/gmail/check request first and
    //     silently dropping its edge Basic Auth challenge.
    //   - /share/*.json MUST precede /share/* so view-counted reads never
    //     fall through to a raw, uncounted S3 fetch.
    const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {};

    if (pollerFnUrl) {
      additionalBehaviors['/api/gmail/check'] = {
        origin: origins.FunctionUrlOrigin.withOriginAccessControl(pollerFnUrl),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        // Only attached when basicAuthCredentialBase64 was supplied — see
        // its prop doc comment. Without it this owner-only route deploys
        // without the extra edge Basic Auth challenge.
        ...(basicAuthFn
          ? { functionAssociations: [{ function: basicAuthFn, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }] }
          : {}),
      };
    }

    additionalBehaviors['/share/*.json'] = {
      origin: lambdaOrigin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
    };

    // Single catch-all for every /api/* route. This used to be split
    // per-path (/api/invoke, /api/drive/*, each with its own allowed
    // methods) until /api/me shipped in the Lambda with no matching
    // behavior and silently 405'd at the S3 default behavior instead of
    // ever reaching the Lambda. ALLOW_ALL + the same origin/cache/auth
    // posture as before means any future /api/<x> route the Lambda adds is
    // routed automatically — no CDK change, no chance of repeating this bug.
    // Auth is still all inside the Lambda (Cognito ID token), never at the
    // edge.
    additionalBehaviors['/api/*'] = {
      origin: lambdaOrigin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
    };

    additionalBehaviors['/share/*'] = {
      origin: s3Origin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
    };

    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: 'poc-validator-agentcore-demo HTTPS front',
      // OPTIONAL: the CLOUDFRONT-scope WAFv2 Web ACL ARN from the sibling
      // PocValidatorWafStack (always us-east-1 — see infrastructure/cdk/lib/waf-stack.ts
      // and bin/web.ts for why that has to be a separate stack). Left
      // undefined simply deploys without a WAF attached rather than failing
      // the whole stack.
      webAclId: props.webAclArn,
      defaultBehavior: {
        // Public self-service: no edge Basic Auth. Abuse protection now
        // lives in the WAF web ACL above + Cognito JWT + quota in the
        // Lambda (see source/api/handler.py _authenticate/_consume_credit).
        origin: s3Origin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: 'index.html',
      additionalBehaviors,
    });

    // CDK's FunctionUrlOrigin.withOriginAccessControl() grants only
    // lambda:InvokeFunctionUrl. As of the "Dual Auth" requirement Lambda
    // rolled out for Function URLs, CloudFront also needs plain
    // lambda:InvokeFunction on the same principal/condition, or every
    // request 403s with the generic "Forbidden" Function-URL-auth error —
    // hit this for real on this stack's first deploy. See
    // https://github.com/aws/aws-cdk/issues/35872 (still open as of writing).
    webInvokeFn.addPermission('AllowCloudFrontInvokeFunction', {
      principal: new iam.ServicePrincipal('cloudfront.amazonaws.com'),
      action: 'lambda:InvokeFunction',
      sourceArn: `arn:aws:cloudfront::${this.account}:distribution/${distribution.distributionId}`,
    });

    // Committed static pages (source/web/) deployed to the site bucket, plus
    // the (non-secret) Cognito config the browser needs to call InitiateAuth
    // directly. prune MUST stay false: the bucket also holds live
    // share/<id>.json results, the out-of-band config/banned-clients.json,
    // and any pages that predate source control — pruning would delete them
    // all.
    new s3deploy.BucketDeployment(this, 'SiteDeployment', {
      sources: [
        s3deploy.Source.asset(path.join(__dirname, '..', '..', '..', '..', 'source', 'web')),
        s3deploy.Source.jsonData('config/auth.json', {
          region: this.region,
          userPoolId: userPool.userPoolId,
          clientId: userPoolClient.userPoolClientId,
          // Tells the UI whether mode="agent" is worth offering at all —
          // true one-click installs (no AgentCore runtime configured) are
          // Tier-1-only; see agentRuntimeArn's prop doc comment.
          agentEnabled: !!props.agentRuntimeArn,
          // Lets the page show/enforce the real server-side upload cap
          // instead of a hardcoded string — see maxUploadBytes prop doc
          // comment and handler.py's MAX_DOCUMENT_BYTES.
          maxUploadBytes: props.maxUploadBytes ?? DEFAULT_MAX_UPLOAD_BYTES,
        }),
      ],
      destinationBucket: siteBucket,
      prune: false,
      distribution,
      distributionPaths: ['/', '/index.html', '/sample.html', '/config/auth.json'],
    });

    new CfnOutput(this, 'DistributionDomainName', {
      value: distribution.distributionDomainName,
      description:
        'Redeploy this stack passing this value (as https://<this>) via publicBaseUrl ' +
        "if it doesn't already match what the Lambda has for ALLOWED_ORIGIN/PUBLIC_BASE_URL.",
    });

    // ---- OPTIONAL: email-in / email-out SOW reviews ------------------------
    // Gated on emailDomain the same way the Drive feature gates on its secret:
    // unset means none of this exists and the rest of the stack is unchanged.
    if (props.emailDomain) {
      const sowAddress = `sow@${props.emailDomain}`;

      // Raw inbound MIME lands here; nothing needs to outlive a month.
      const mailBucket = new s3.Bucket(this, 'MailBucket', {
        bucketName: `poc-validator-mail-${this.account}`,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        encryption: s3.BucketEncryption.S3_MANAGED,
        removalPolicy: RemovalPolicy.RETAIN,
        lifecycleRules: [{ id: 'expire-inbound-mail-30d', enabled: true, expiration: Duration.days(30) }],
      });

      // Verifying the domain identity yields the DKIM records to publish;
      // Easy DKIM also serves as domain verification.
      const emailIdentity = new ses.EmailIdentity(this, 'EmailIdentity', {
        identity: ses.Identity.domain(props.emailDomain),
      });

      const emailFn = new lambda.Function(this, 'EmailReviewFunction', {
        functionName: 'poc-validator-email-review',
        runtime: lambda.Runtime.PYTHON_3_13,
        handler: 'email_review.handler',
        code: bundledCode,
        timeout: Duration.minutes(2),
        memorySize: 512,
        environment: {
          FROM_ADDRESS: sowAddress,
          CONFIG_BUCKET: siteBucket.bucketName,
          ALLOWED_SENDERS: props.emailAllowedSenders ?? '',
          POCVALIDATOR_ROOT: '/var/task',
        },
      });
      emailFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [
            mailBucket.arnForObjects('inbox/*'),
            siteBucket.arnForObjects('config/banned-clients.json'),
          ],
        })
      );
      emailFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['ses:SendEmail'],
          resources: ['*'],
          conditions: { StringEquals: { 'ses:FromAddress': sowAddress } },
        })
      );
      mailBucket.addEventNotification(
        s3.EventType.OBJECT_CREATED,
        new s3n.LambdaDestination(emailFn),
        { prefix: 'inbox/' }
      );

      // Receipt rule: scan, then store under inbox/ (which fires the Lambda).
      // The sesActions.S3 action wires the bucket policy SES needs.
      const ruleSet = new ses.ReceiptRuleSet(this, 'SowReceiptRuleSet', {
        receiptRuleSetName: 'poc-validator-sow-inbound',
        rules: [
          {
            recipients: [sowAddress],
            scanEnabled: true,
            actions: [new sesActions.S3({ bucket: mailBucket, objectKeyPrefix: 'inbox/' })],
          },
        ],
      });

      // SES has exactly one ACTIVE rule set account-wide and CloudFormation
      // cannot activate one — flip it with a custom resource. Deleting the
      // stack deactivates (empty parameters) rather than orphaning a pointer
      // to a deleted rule set.
      new cr.AwsCustomResource(this, 'ActivateReceiptRuleSet', {
        onCreate: {
          service: 'SES',
          action: 'setActiveReceiptRuleSet',
          parameters: { RuleSetName: ruleSet.receiptRuleSetName },
          physicalResourceId: cr.PhysicalResourceId.of('poc-validator-active-rule-set'),
        },
        onDelete: { service: 'SES', action: 'setActiveReceiptRuleSet', parameters: {} },
        policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
          resources: cr.AwsCustomResourcePolicy.ANY_RESOURCE,
        }),
      });

      new CfnOutput(this, 'SowEmailAddress', {
        value: sowAddress,
        description: 'Send a SOW (.docx/.txt/.md attachment) here; the review comes back by reply.',
      });
      new CfnOutput(this, 'EmailDnsMxRecord', {
        value: `${props.emailDomain} MX 10 inbound-smtp.${this.region}.amazonaws.com`,
        description: 'Publish this MX record at the DNS provider for the email domain.',
      });
      new CfnOutput(this, 'EmailDnsDkimRecords', {
        value: [1, 2, 3]
          .map((i) => {
            const name = (emailIdentity as ses.EmailIdentity).dkimRecords[i - 1];
            return name ? `${name.name} CNAME ${name.value}` : '';
          })
          .filter(Boolean)
          .join(' | '),
        description: 'Publish these three CNAME records to verify the domain (Easy DKIM).',
      });
    }

    // ---- OPTIONAL: AWS-native Gmail poller — wiring that needs the ---------
    // ---- Distribution (function + behavior were created above) ------------
    // Polls the owner's own mailbox for SOWs sent to their +sow alias, acks,
    // reviews in-process (Tier 1), replies with the report, and answers
    // follow-up questions in the thread via the AgentCore runtime. Only the
    // Gmail OAuth token lives outside AWS IAM — held in Secrets Manager.
    if (props.gmailSecretArn && props.gmailOwner && pollerFn) {
      const alias = props.gmailOwner.replace('@', '+sow@');
      // Same Function-URL "Dual Auth" gotcha as webInvokeFn above: OAC grants
      // only lambda:InvokeFunctionUrl; CloudFront needs InvokeFunction too.
      pollerFn.addPermission('AllowCloudFrontInvokeFunction', {
        principal: new iam.ServicePrincipal('cloudfront.amazonaws.com'),
        action: 'lambda:InvokeFunction',
        sourceArn: `arn:aws:cloudfront::${this.account}:distribution/${distribution.distributionId}`,
      });
      new CfnOutput(this, 'GmailSowAlias', {
        value: alias,
        description: 'Forward a SOW here from the owner address, then ping /api/gmail/check.',
      });
      new CfnOutput(this, 'GmailCheckUrl', {
        value: `${props.publicBaseUrl ?? 'https://<distribution>'}/api/gmail/check`,
        description: 'Bookmark this: one tap processes the mailbox and sends the replies.',
      });
    }

    Tags.of(this).add('project', 'poc-validator-agent');
    Tags.of(this).add('layer', 'web');
  }
}

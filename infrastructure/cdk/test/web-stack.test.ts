import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
// Imported from the compiled output (`npm run build` must run first, same as
// `npm run cdk`/`agentcore deploy` do) rather than the TypeScript source.
// web-stack.ts resolves its Lambda asset directory relative to __dirname,
// matching the compiled dist/lib/ location it runs from in a real deploy —
// importing the .ts source directly under ts-jest resolves __dirname one
// level shallower (lib/ instead of dist/lib/) and points at a directory
// that doesn't exist, which is a test-environment artifact, not a bug in
// the deployed stack.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { PocValidatorWebStack } = require('../dist/lib/web-stack');

const RUNTIME_ARN = 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/TestRuntime-abc123';
const TEST_WEB_ACL_ARN =
  'arn:aws:wafv2:us-east-1:123456789012:global/webacl/poc-validator-web-acl/11111111-2222-3333-4444-555555555555';

function synth(
  props?: Partial<{
    agentRuntimeArn: string;
    noAgentRuntime: boolean;
    webAclArn: string;
    noBasicAuthCred: boolean;
    freeRuns: number;
    maxUploadBytes: number;
    selfHostUrl: string;
    publicBaseUrl: string;
    driveSaSecretArn: string;
    driveFolderId: string;
    emailDomain: string;
    emailAllowedSenders: string;
    gmailSecretArn: string;
    gmailOwner: string;
    signupAllowed: string;
  }>
) {
  const app = new cdk.App();
  const stack = new PocValidatorWebStack(app, 'TestWebStack', {
    // Both default to "supplied" so every pre-existing test below keeps its
    // original behavior; opt into the one-click-install (unset) scenarios
    // with noAgentRuntime / noBasicAuthCred.
    agentRuntimeArn: props?.noAgentRuntime ? undefined : (props?.agentRuntimeArn ?? RUNTIME_ARN),
    basicAuthCredentialBase64: props?.noBasicAuthCred ? undefined : 'dGVzdDp0ZXN0', // "test:test"
    demoKey: 'test-demo-key',
    webAclArn: props?.webAclArn,
    freeRuns: props?.freeRuns,
    maxUploadBytes: props?.maxUploadBytes,
    selfHostUrl: props?.selfHostUrl,
    publicBaseUrl: props?.publicBaseUrl,
    driveSaSecretArn: props?.driveSaSecretArn,
    driveFolderId: props?.driveFolderId,
    emailDomain: props?.emailDomain,
    emailAllowedSenders: props?.emailAllowedSenders,
    gmailSecretArn: props?.gmailSecretArn,
    gmailOwner: props?.gmailOwner,
    signupAllowed: props?.signupAllowed,
  });
  return Template.fromStack(stack);
}

// Region/userPoolId/clientId are CDK tokens, so s3deploy.Source.jsonData
// bakes them into config/auth.json as <<marker:...>> placeholders resolved
// only at deploy time by the BucketDeployment custom resource — Template
// assertions (CFN JSON) never see the real auth.json content. Literal
// values (agentEnabled, maxUploadBytes) ARE written verbatim into the
// staged asset file, though, so read that file directly off disk via a
// real (non-Template) synth to assert on them.
function synthAuthJson(props?: Partial<{ noAgentRuntime: boolean; maxUploadBytes: number }>): string {
  const outdir = fs.mkdtempSync(path.join(os.tmpdir(), 'pv-web-stack-test-'));
  const app = new cdk.App({ outdir });
  new PocValidatorWebStack(app, 'TestWebStack', {
    agentRuntimeArn: props?.noAgentRuntime ? undefined : RUNTIME_ARN,
    basicAuthCredentialBase64: 'dGVzdDp0ZXN0',
    demoKey: 'test-demo-key',
    maxUploadBytes: props?.maxUploadBytes,
  });
  app.synth();
  const assetDirs = fs.readdirSync(outdir).filter(f => f.startsWith('asset.'));
  for (const dir of assetDirs) {
    const candidate = path.join(outdir, dir, 'config', 'auth.json');
    if (fs.existsSync(candidate)) {
      return fs.readFileSync(candidate, 'utf8');
    }
  }
  throw new Error(`config/auth.json asset not found under ${outdir}`);
}

describe('PocValidatorWebStack', () => {
  test('synthesizes cleanly with and without publicBaseUrl', () => {
    expect(() => synth()).not.toThrow();
    expect(() => synth({ publicBaseUrl: 'https://example.cloudfront.net' })).not.toThrow();
  });

  test('synthesizes cleanly with NO agentRuntimeArn, NO basicAuthCredentialBase64, and NO webAclArn — the true one-click, zero-manual-prerequisite install', () => {
    expect(() => synth({ noAgentRuntime: true, noBasicAuthCred: true })).not.toThrow();
  });

  test('no email resources exist unless emailDomain is set', () => {
    const template = synth();
    template.resourceCountIs('AWS::SES::ReceiptRuleSet', 0);
    expect(() =>
      template.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'poc-validator-email-review',
      })
    ).toThrow();
  });

  test('gmailSecretArn + gmailOwner gate the Gmail poller', () => {
    const bare = synth();
    expect(() =>
      bare.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'poc-validator-gmail-poller',
      })
    ).toThrow();

    const template = synth({
      gmailSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:gmail-abc',
      gmailOwner: 'me@example.com',
    });
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-gmail-poller',
      Handler: 'gmail_poller.handler',
      Environment: {
        Variables: Match.objectLike({
          OWNER_EMAIL: 'me@example.com',
          ALIAS_EMAIL: 'me+sow@example.com',
        }),
      },
    });
    // Event-driven: no schedule anywhere; the trigger is the owner's ping
    // on the CloudFront route, behind the same Basic Auth as the site.
    template.resourceCountIs('AWS::Events::Rule', 0);
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({
            PathPattern: '/api/gmail/check',
            FunctionAssociations: Match.arrayWith([
              Match.objectLike({ EventType: 'viewer-request' }),
            ]),
          }),
        ]),
      }),
    });
  });

  test('gmailSecretArn/gmailOwner without a basicAuthCredentialBase64 deploys /api/gmail/check without edge Basic Auth, rather than failing synth', () => {
    const template = synth({
      noBasicAuthCred: true,
      gmailSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:gmail-abc',
      gmailOwner: 'me@example.com',
    });
    expect(() =>
      template.hasResourceProperties('AWS::CloudFront::Function', {
        FunctionConfig: Match.objectLike({}),
      })
    ).toThrow(); // BasicAuthFunction itself must not exist
    const dist = Object.values(template.findResources('AWS::CloudFront::Distribution'))[0] as any;
    const gmailCheck = dist.Properties.DistributionConfig.CacheBehaviors.find(
      (b: any) => b.PathPattern === '/api/gmail/check'
    );
    expect(gmailCheck.FunctionAssociations ?? []).toHaveLength(0);
  });

  test('emailDomain gates the full inbound pipeline', () => {
    const template = synth({
      emailDomain: 'review.example.com',
      emailAllowedSenders: 'me@example.com',
    });
    template.resourceCountIs('AWS::SES::ReceiptRuleSet', 1);
    template.hasResourceProperties('AWS::SES::ReceiptRule', {
      Rule: Match.objectLike({
        Recipients: ['sow@review.example.com'],
        ScanEnabled: true,
      }),
    });
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-email-review',
      Handler: 'email_review.handler',
      Environment: {
        Variables: Match.objectLike({
          FROM_ADDRESS: 'sow@review.example.com',
          ALLOWED_SENDERS: 'me@example.com',
        }),
      },
    });
    // Outbound is pinned to the pipeline's own From address.
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'ses:SendEmail',
            Condition: { StringEquals: { 'ses:FromAddress': 'sow@review.example.com' } },
          }),
        ]),
      }),
    });
  });

  test('the results bucket blocks all public access and retains its 30-day share lifecycle rule', () => {
    const template = synth();
    template.hasResourceProperties('AWS::S3::Bucket', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
      LifecycleConfiguration: {
        Rules: Match.arrayWith([
          Match.objectLike({
            ExpirationInDays: 30,
            Prefix: 'share/',
            Status: 'Enabled',
            TagFilters: [{ Key: 'AutoExpire', Value: 'true' }],
          }),
        ]),
      },
    });
  });

  test('the view-count table uses on-demand billing and a TTL attribute (not RCU/WCU provisioning)', () => {
    const template = synth();
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
      TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
      KeySchema: [{ AttributeName: 'share_id', KeyType: 'HASH' }],
    });
  });

  test('UsersTable (quota) is on-demand, keyed on user_sub, and torn down with the stack (RemovalPolicy.DESTROY)', () => {
    const template = synth();
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
      KeySchema: [{ AttributeName: 'user_sub', KeyType: 'HASH' }],
    });
    const tables = template.findResources('AWS::DynamoDB::Table', {
      Properties: Match.objectLike({ KeySchema: [{ AttributeName: 'user_sub', KeyType: 'HASH' }] }),
    });
    const [, usersTable] = Object.entries(tables)[0] as [string, any];
    expect(usersTable.DeletionPolicy).toBe('Delete');
  });

  test('a self-sign-up Cognito user pool exists with email verification-by-code and a public app client', () => {
    const template = synth();
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      AdminCreateUserConfig: Match.objectLike({ AllowAdminCreateUserOnly: false }),
      AutoVerifiedAttributes: ['email'],
      Policies: Match.objectLike({
        PasswordPolicy: Match.objectLike({
          MinimumLength: 8,
          RequireLowercase: true,
          RequireUppercase: true,
          RequireNumbers: true,
        }),
      }),
    });
    const pools = template.findResources('AWS::Cognito::UserPool');
    expect((Object.values(pools)[0] as any).DeletionPolicy).toBe('Delete');

    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      ExplicitAuthFlows: Match.arrayWith(['ALLOW_USER_PASSWORD_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH']),
      GenerateSecret: false,
    });
  });

  test('the user pool is wired with a PreSignUp Lambda trigger enforcing the email allowlist', () => {
    const template = synth();
    // LambdaConfig.PreSignUp on the pool itself must point at the trigger
    // function's ARN — this is what actually makes Cognito invoke it.
    const fns = template.findResources('AWS::Lambda::Function', {
      Properties: Match.objectLike({ FunctionName: 'poc-validator-presignup' }),
    });
    const [fnLogicalId] = Object.keys(fns);
    expect(fnLogicalId).toBeDefined();

    template.hasResourceProperties('AWS::Cognito::UserPool', {
      LambdaConfig: Match.objectLike({
        PreSignUp: { 'Fn::GetAtt': [fnLogicalId, 'Arn'] },
      }),
    });

    // Cognito needs explicit permission to invoke the trigger.
    template.hasResourceProperties('AWS::Lambda::Permission', {
      Action: 'lambda:InvokeFunction',
      FunctionName: { 'Fn::GetAtt': [fnLogicalId, 'Arn'] },
      Principal: 'cognito-idp.amazonaws.com',
    });

    // Default allowlist (this project's own) flows into the trigger's env
    // when signupAllowed is left unset.
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-presignup',
      Environment: {
        Variables: Match.objectLike({ SIGNUP_ALLOWED: 'amazon.com,schinchli@gmail.com' }),
      },
    });
  });

  test('signupAllowed flows into both the PreSignUp trigger and the web Lambda (defence in depth); empty string is preserved, not defaulted', () => {
    const template = synth({ signupAllowed: 'example.com,someone@else.test' });
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-presignup',
      Environment: {
        Variables: Match.objectLike({ SIGNUP_ALLOWED: 'example.com,someone@else.test' }),
      },
    });
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-web-invoke',
      Environment: {
        Variables: Match.objectLike({ SIGNUP_ALLOWED: 'example.com,someone@else.test' }),
      },
    });

    const openTemplate = synth({ signupAllowed: '' });
    openTemplate.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-presignup',
      Environment: { Variables: Match.objectLike({ SIGNUP_ALLOWED: '' }) },
    });
  });

  test('the web Lambda gets Cognito + quota config in its environment and read/write access to UsersTable', () => {
    const template = synth();
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-web-invoke',
      Environment: {
        Variables: Match.objectLike({
          USER_POOL_ID: Match.anyValue(),
          USER_POOL_CLIENT_ID: Match.anyValue(),
          USERS_TABLE: Match.anyValue(),
          FREE_RUNS: '1',
          SELF_HOST_URL: Match.anyValue(),
        }),
      },
    });
    const policies = template.findResources('AWS::IAM::Policy');
    const statements = Object.entries(policies)
      .filter(([id]) => id.startsWith('WebInvokeFunction'))
      .flatMap(([, p]: [string, any]) => p.Properties.PolicyDocument.Statement);
    expect(statements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Action: expect.arrayContaining(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem']),
        }),
      ])
    );
  });

  test('freeRuns and selfHostUrl props flow into the Lambda environment', () => {
    const template = synth({ freeRuns: 3, selfHostUrl: 'https://example.com/fork-me' });
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-web-invoke',
      Environment: {
        Variables: Match.objectLike({
          FREE_RUNS: '3',
          SELF_HOST_URL: 'https://example.com/fork-me',
        }),
      },
    });
  });

  test('maxUploadBytes defaults to 5 MB (5242880) and a custom value flows into the Lambda environment as MAX_UPLOAD_BYTES', () => {
    const defaultTemplate = synth();
    defaultTemplate.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-web-invoke',
      Environment: { Variables: Match.objectLike({ MAX_UPLOAD_BYTES: '5242880' }) },
    });

    const customTemplate = synth({ maxUploadBytes: 10485760 });
    customTemplate.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-web-invoke',
      Environment: { Variables: Match.objectLike({ MAX_UPLOAD_BYTES: '10485760' }) },
    });
  });

  test('agentRuntimeArn is OPTIONAL: omitting it still deploys, with an empty ARN and no bedrock-agentcore IAM grant', () => {
    const template = synth({ noAgentRuntime: true });
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'poc-validator-web-invoke',
      Environment: { Variables: Match.objectLike({ AGENT_RUNTIME_ARN: '' }) },
    });
    const policies = template.findResources('AWS::IAM::Policy');
    const actions = Object.values(policies)
      .flatMap((p: any) => p.Properties.PolicyDocument.Statement)
      .flatMap((s: any) => (Array.isArray(s.Action) ? s.Action : [s.Action]));
    expect(actions).not.toContain('bedrock-agentcore:InvokeAgentRuntime');
  });

  test('auth.json is published with region/userPoolId/clientId/agentEnabled, prune stays false', () => {
    const withAgent = synth();
    const withoutAgent = synth({ noAgentRuntime: true });
    for (const template of [withAgent, withoutAgent]) {
      const deployments = template.findResources('Custom::CDKBucketDeployment');
      expect(Object.keys(deployments).length).toBeGreaterThan(0);
      for (const [, res] of Object.entries(deployments)) {
        expect((res as any).Properties.Prune).toBe(false);
      }
    }
  });

  test('auth.json carries maxUploadBytes: default 5242880, or the custom value when maxUploadBytes is set', () => {
    const defaultAuthJson = JSON.parse(
      synthAuthJson().replace(/<<marker:[^>]+>>/g, '"__marker__"')
    );
    expect(defaultAuthJson.maxUploadBytes).toBe(5242880);
    expect(defaultAuthJson.agentEnabled).toBe(true);

    const customAuthJson = JSON.parse(
      synthAuthJson({ maxUploadBytes: 10485760 }).replace(/<<marker:[^>]+>>/g, '"__marker__"')
    );
    expect(customAuthJson.maxUploadBytes).toBe(10485760);
  });

  test("the Lambda's IAM policy is scoped to specific actions and resources, never a wildcard", () => {
    const template = synth();
    const policies = template.findResources('AWS::IAM::Policy');
    // Scope to the policies this stack authors for its own Lambda. The
    // BucketDeployment construct vends its own handler whose CloudFront
    // invalidation grant is Resource:"*" by CDK design — that handler is
    // CDK-managed code, not part of the contract this test protects.
    const statements = Object.entries(policies)
      .filter(([id]) => id.startsWith('WebInvokeFunction'))
      .flatMap(([, p]: [string, any]) => p.Properties.PolicyDocument.Statement);

    // Every statement this stack authored must name its actions explicitly and
    // must not grant Resource: "*" — this is the property the CDK dual-auth
    // gap and the L2 grant*() convenience methods were both deliberately
    // avoided to preserve (see the comment above addToRolePolicy in
    // web-stack.ts).
    for (const statement of statements) {
      expect(statement.Action).not.toBe('*');
      if (Array.isArray(statement.Action)) {
        expect(statement.Action).not.toContain('*');
      }
      expect(statement.Resource).not.toBe('*');
    }

    expect(statements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Action: 'bedrock-agentcore:InvokeAgentRuntime',
          Resource: [RUNTIME_ARN, `${RUNTIME_ARN}/runtime-endpoint/*`],
        }),
      ])
    );
  });

  test('CloudFront grants the Lambda plain lambda:InvokeFunction, not just InvokeFunctionUrl (the dual-auth fix)', () => {
    // Regression test for the CDK dual-auth gap documented in web-stack.ts
    // and https://github.com/aws/aws-cdk/issues/35872 — FunctionUrlOrigin
    // .withOriginAccessControl() alone only grants lambda:InvokeFunctionUrl,
    // which 403s every request under Lambda's Function URL "Dual Auth"
    // requirement without this explicit permission alongside it.
    const template = synth();
    template.hasResourceProperties('AWS::Lambda::Permission', {
      Action: 'lambda:InvokeFunction',
      Principal: 'cloudfront.amazonaws.com',
    });
  });

  test('CloudFront routes /share/*.json ahead of /share/* so view-counted reads never fall through to raw S3', () => {
    const template = synth();
    const distributions = template.findResources('AWS::CloudFront::Distribution');
    const [, distribution] = Object.entries(distributions)[0];
    const behaviors: any[] = (distribution as any).Properties.DistributionConfig.CacheBehaviors;

    const patterns = behaviors.map(b => b.PathPattern);
    const jsonIndex = patterns.indexOf('/share/*.json');
    const shareIndex = patterns.indexOf('/share/*');

    expect(jsonIndex).toBeGreaterThanOrEqual(0);
    expect(shareIndex).toBeGreaterThanOrEqual(0);
    expect(jsonIndex).toBeLessThan(shareIndex);
  });

  test('Basic Auth is removed from every public behavior — the site is public self-service now', () => {
    const template = synth();
    const distributions = template.findResources('AWS::CloudFront::Distribution');
    const [, distribution] = Object.entries(distributions)[0];
    const config = (distribution as any).Properties.DistributionConfig;

    expect(config.DefaultCacheBehavior.FunctionAssociations ?? []).toHaveLength(0);

    for (const pattern of ['/api/*', '/share/*']) {
      const behavior = config.CacheBehaviors.find((b: any) => b.PathPattern === pattern);
      expect(behavior.FunctionAssociations ?? []).toHaveLength(0);
    }
  });

  test('Basic Auth still guards the owner-only /api/gmail/check route when a credential is supplied', () => {
    const template = synth({
      gmailSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:gmail-abc',
      gmailOwner: 'me@example.com',
    });
    const dist = Object.values(template.findResources('AWS::CloudFront::Distribution'))[0] as any;
    const gmailCheck = dist.Properties.DistributionConfig.CacheBehaviors.find(
      (b: any) => b.PathPattern === '/api/gmail/check'
    );
    expect(gmailCheck.FunctionAssociations).toEqual(
      expect.arrayContaining([expect.objectContaining({ EventType: 'viewer-request' })])
    );
  });

  test('ALLOWED_ORIGIN and PUBLIC_BASE_URL fall back to safe defaults when publicBaseUrl is not yet known (first deploy)', () => {
    const template = synth();
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: Match.objectLike({
          ALLOWED_ORIGIN: '*',
          PUBLIC_BASE_URL: '',
        }),
      },
    });
  });

  test('/api/* is a single catch-all behavior on the Lambda origin allowing every method (including POST), so /api/me — and any future route — needs no CDK change; uncached, public (Cognito JWT checked in the Lambda, not edge Basic Auth), and precedes /share/*', () => {
    const template = synth();
    const dist = Object.values(template.findResources('AWS::CloudFront::Distribution'))[0] as any;
    const behaviors = dist.Properties.DistributionConfig.CacheBehaviors as any[];
    const patterns = behaviors.map((b) => b.PathPattern);

    const api = behaviors.find((b) => b.PathPattern === '/api/*');
    expect(api).toBeDefined();
    expect(api.AllowedMethods).toEqual(
      expect.arrayContaining(['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'])
    );
    expect(api.FunctionAssociations ?? []).toHaveLength(0);
    expect(patterns.indexOf('/api/*')).toBeLessThan(patterns.indexOf('/share/*'));

    // The old per-path behaviors are gone — /api/me's bug (a new Lambda
    // route with no matching CacheBehavior, falling through to the S3
    // default behavior) can't recur because there's no per-path list left
    // to forget an entry on.
    expect(patterns).not.toContain('/api/invoke');
    expect(patterns).not.toContain('/api/drive/*');
  });

  test('/api/gmail/check precedes /api/* in CacheBehaviors — the wildcard must not shadow the more specific, Basic-Auth-gated owner-only route (CloudFront matches path patterns in list order, not by specificity)', () => {
    const template = synth({
      gmailSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:gmail-abc',
      gmailOwner: 'me@example.com',
    });
    const dist = Object.values(template.findResources('AWS::CloudFront::Distribution'))[0] as any;
    const patterns = (dist.Properties.DistributionConfig.CacheBehaviors as any[]).map((b) => b.PathPattern);
    const gmailIndex = patterns.indexOf('/api/gmail/check');
    const apiIndex = patterns.indexOf('/api/*');
    expect(gmailIndex).toBeGreaterThanOrEqual(0);
    expect(apiIndex).toBeGreaterThanOrEqual(0);
    expect(gmailIndex).toBeLessThan(apiIndex);
  });

  test('Drive stays cleanly unconfigured by default: empty env vars, no Secrets Manager grant', () => {
    const template = synth();
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: Match.objectLike({ DRIVE_SA_SECRET_ARN: '', DRIVE_FOLDER_ID: '' }),
      },
    });
    const policies = template.findResources('AWS::IAM::Policy');
    const actions = Object.values(policies)
      .flatMap((p: any) => p.Properties.PolicyDocument.Statement)
      .flatMap((s: any) => (Array.isArray(s.Action) ? s.Action : [s.Action]));
    expect(actions).not.toContain('secretsmanager:GetSecretValue');
  });

  test('providing driveSaSecretArn grants GetSecretValue on exactly that secret', () => {
    const template = synth({
      driveSaSecretArn: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:drive-sa-abc123',
      driveFolderId: 'folder123',
    } as any);
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'secretsmanager:GetSecretValue',
            Resource: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:drive-sa-abc123',
          }),
        ]),
      }),
    });
  });

  test('site deployment never prunes — live share results and out-of-band config must survive deploys', () => {
    const template = synth();
    template.hasResourceProperties('Custom::CDKBucketDeployment', {
      Prune: false,
    });
  });

  test('ALLOWED_ORIGIN and PUBLIC_BASE_URL are set once publicBaseUrl is known (second deploy)', () => {
    const template = synth({ publicBaseUrl: 'https://d123.cloudfront.net' });
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: Match.objectLike({
          ALLOWED_ORIGIN: 'https://d123.cloudfront.net',
          PUBLIC_BASE_URL: 'https://d123.cloudfront.net',
        }),
      },
    });
  });

  test('webAclArn is OPTIONAL: providing it sets WebACLId on the distribution, omitting it deploys without a WAF rather than failing', () => {
    const withWaf = synth({ webAclArn: TEST_WEB_ACL_ARN });
    withWaf.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({ WebACLId: TEST_WEB_ACL_ARN }),
    });

    const withoutWaf = synth();
    const dist = Object.values(withoutWaf.findResources('AWS::CloudFront::Distribution'))[0] as any;
    expect(dist.Properties.DistributionConfig.WebACLId).toBeUndefined();
  });
});

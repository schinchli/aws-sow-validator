#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { PocValidatorWebStack } from '../lib/web-stack';
import { PocValidatorWafStack } from '../lib/waf-stack';

const app = new cdk.App();

const account = process.env.CDK_DEFAULT_ACCOUNT;
const region = process.env.CDK_DEFAULT_REGION ?? 'us-east-1';

const freeRunsContext = app.node.tryGetContext('freeRuns');
const maxUploadBytesContext = app.node.tryGetContext('maxUploadBytes');

// CLOUDFRONT-scope WAFv2 must live in us-east-1 regardless of where the main
// stack deploys — see infrastructure/cdk/lib/waf-stack.ts. `crossRegionReferences`
// lets PocValidatorWebStack (below) consume this stack's Web ACL ARN even
// when `region` here is something else. Running `cdk deploy
// PocValidatorWebStack` alone still deploys this stack first automatically
// — CDK follows the stack dependency the cross-stack reference creates —
// so the whole thing stays a single command.
const wafStack = new PocValidatorWafStack(app, 'PocValidatorWafStack', {
  env: { account, region: 'us-east-1' },
  crossRegionReferences: true,
});

new PocValidatorWebStack(app, 'PocValidatorWebStack', {
  env: { account, region },
  crossRegionReferences: true,
  webAclArn: wafStack.webAclArn,
  // All OPTIONAL — a bare `cdk deploy` with none of these context values set
  // still produces a working, public, Tier-1-only (no Bedrock/AgentCore
  // access needed) deployment. See each prop's doc comment in web-stack.ts.
  agentRuntimeArn: app.node.tryGetContext('agentRuntimeArn'),
  demoKey: app.node.tryGetContext('demoKey'),
  basicAuthCredentialBase64: app.node.tryGetContext('basicAuthCredentialBase64'),
  freeRuns: freeRunsContext !== undefined ? Number(freeRunsContext) : undefined,
  // OPTIONAL: raise/lower the server-side upload cap (bytes) on sow_text +
  // diagram_text. Defaults to 5 MB (5242880) in web-stack.ts. Pass
  // `-c maxUploadBytes=10485760` on a fork to change it without editing code.
  maxUploadBytes: maxUploadBytesContext !== undefined ? Number(maxUploadBytesContext) : undefined,
  selfHostUrl: app.node.tryGetContext('selfHostUrl'),
  publicBaseUrl: app.node.tryGetContext('publicBaseUrl'),
  driveSaSecretArn: app.node.tryGetContext('driveSaSecretArn'),
  driveFolderId: app.node.tryGetContext('driveFolderId'),
  emailDomain: app.node.tryGetContext('emailDomain'),
  emailAllowedSenders: app.node.tryGetContext('emailAllowedSenders'),
  gmailSecretArn: app.node.tryGetContext('gmailSecretArn'),
  gmailOwner: app.node.tryGetContext('gmailOwner'),
  // OPTIONAL: comma-separated sign-up allowlist (see web-stack.ts prop doc
  // comment + source/api/allowlist.py). Unset falls back to this project's
  // own allowlist; pass `-c signupAllowed=""` to allow open sign-up on a
  // fork, or `-c signupAllowed="yourdomain.com,you@example.com"` for a
  // custom one.
  signupAllowed: app.node.tryGetContext('signupAllowed'),
});

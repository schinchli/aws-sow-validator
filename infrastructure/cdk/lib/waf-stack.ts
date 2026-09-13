import { CfnOutput, Stack, StackProps, Token } from 'aws-cdk-lib';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

/**
 * Standalone stack for the CLOUDFRONT-scope WAFv2 Web ACL that protects the
 * public site's distribution (see PocValidatorWebStack in web-stack.ts).
 *
 * WHY A SEPARATE STACK: AWS requires a WAFv2 Web ACL with scope=CLOUDFRONT
 * to be created in us-east-1, full stop — regardless of which region the
 * CloudFront distribution's own stack deploys to. PocValidatorWebStack is
 * meant to deploy into *any* region (that's the one-click-deploy story), so
 * the WAF can't live inside it directly.
 *
 * HOW IT'S WIRED: this stack is always instantiated with
 * `env: { region: 'us-east-1' }` (see bin/web.ts) alongside
 * `crossRegionReferences: true` on both this stack and PocValidatorWebStack.
 * That CDK feature lets PocValidatorWebStack reference `webAclArn` below
 * even when it deploys to a different region — CDK synthesizes the
 * SSM-parameter-backed cross-region export/import plumbing automatically at
 * `cdk deploy` time. No manual ARN copy-paste, no pre-existing resource, no
 * extra step beyond a normal `cdk bootstrap` in both regions (which any CDK
 * deploy already needs). This keeps `cdk deploy --all` a genuine one-command
 * deploy into a fresh account.
 *
 * If you deploy PocValidatorWebStack without this stack (e.g. `webAclArn`
 * left unset), the distribution simply has no WAF attached — see the
 * `webAclArn` prop doc comment on PocValidatorWebStackProps.
 */
export class PocValidatorWafStack extends Stack {
  public readonly webAclArn: string;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Guard against a copy/paste mistake wiring this stack to the wrong
    // region — the only real hard requirement in this whole app. Only
    // enforceable when the region was passed as a literal (as bin/web.ts
    // always does for this stack); an environment-agnostic stack's region
    // is an unresolved token and skips this check, deferring the same
    // failure to CloudFormation at deploy time instead.
    if (!Token.isUnresolved(this.region) && this.region !== 'us-east-1') {
      throw new Error(
        `PocValidatorWafStack must be deployed to us-east-1 (a CLOUDFRONT-scope ` +
          `WAFv2 Web ACL requirement), got "${this.region}". Pass ` +
          `env: { region: 'us-east-1' } when instantiating this stack.`
      );
    }

    const webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: 'poc-validator-web-acl',
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'PocValidatorWebAcl',
      },
      rules: [
        {
          name: 'AWSManagedRulesCommonRuleSet',
          priority: 0,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              // SizeRestrictions_BODY blocks request bodies over 8 KB. This API
              // exists to receive Scope of Work documents: a short SOW extracts
              // to ~24 KB of text, so every real submission was rejected with a
              // 403 WAF block page before it ever reached the Lambda.
              //
              // Counting instead of blocking is safe here because the payload is
              // already bounded on three sides: the Lambda enforces
              // MAX_UPLOAD_BYTES, /api/* requires a verified Cognito token, and
              // the rate-based rule caps requests per IP. The metric is retained
              // so oversized bodies remain visible in CloudWatch.
              ruleActionOverrides: [
                { name: 'SizeRestrictions_BODY', actionToUse: { count: {} } },
              ],
            },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'CommonRuleSet',
          },
        },
        {
          name: 'AWSManagedRulesAmazonIpReputationList',
          priority: 1,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesAmazonIpReputationList' },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'IpReputationList',
          },
        },
        // 300 requests / 5 min per IP, block on exceed.
        {
          name: 'RateLimitPerIp',
          priority: 2,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 300,
              evaluationWindowSec: 300,
              aggregateKeyType: 'IP',
            },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'RateLimitPerIp',
          },
        },
        // NOTE: a CAPTCHA-on-/api/* rule used to live here (priority 3). It
        // was removed — do not reintroduce it. Two independent reasons:
        //   1. A CAPTCHA challenge cannot be satisfied by a programmatic
        //      fetch()/XHR, and every call from the app's own front end to
        //      /api/* IS exactly that — so it broke the whole API in
        //      production (WAF returned the challenge as HTTP 405 with
        //      x-amzn-waf-action: captcha instead of reaching the Lambda).
        //   2. It was protecting nothing that needed it: /api/* already
        //      requires a verified Cognito ID token (checked in the Lambda,
        //      see source/api/handler.py), and sign-up traffic goes straight
        //      to cognito-idp.<region>.amazonaws.com, never through
        //      CloudFront — so this WAF never even saw a sign-up request.
        // Bot/abuse mitigation for /api/* is handled by the managed rule
        // groups and the rate-based rule above instead.
      ],
    });

    this.webAclArn = webAcl.attrArn;

    new CfnOutput(this, 'WebAclArn', {
      value: webAcl.attrArn,
      description: 'Pass as PocValidatorWebStack\'s webAclArn prop to attach this WAF to the distribution.',
    });
  }
}

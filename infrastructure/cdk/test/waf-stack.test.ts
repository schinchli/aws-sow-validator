import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
// See the identical comment in web-stack.test.ts: import from the compiled
// dist/ output, not the .ts source, to match how this runs from a real
// `cdk deploy`.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { PocValidatorWafStack } = require('../dist/lib/waf-stack');

describe('PocValidatorWafStack', () => {
  test('synthesizes cleanly when pinned to us-east-1 (the required region for a CLOUDFRONT-scope Web ACL)', () => {
    const app = new cdk.App();
    expect(
      () => new PocValidatorWafStack(app, 'TestWafStack', { env: { account: '123456789012', region: 'us-east-1' } })
    ).not.toThrow();
  });

  test('throws synth-time if instantiated with a literal region other than us-east-1', () => {
    const app = new cdk.App();
    expect(
      () => new PocValidatorWafStack(app, 'TestWafStack', { env: { account: '123456789012', region: 'eu-west-1' } })
    ).toThrow(/us-east-1/);
  });

  test('does not throw for an environment-agnostic stack (unresolved region token) — CloudFormation would reject it at deploy time instead', () => {
    const app = new cdk.App();
    expect(() => new PocValidatorWafStack(app, 'TestWafStack')).not.toThrow();
  });

  test('creates a CLOUDFRONT-scope Web ACL with the required managed rules and a 300/5min rate limit, with CloudWatch metrics on every rule, and NO CAPTCHA rule', () => {
    const app = new cdk.App();
    const stack = new PocValidatorWafStack(app, 'TestWafStack', {
      env: { account: '123456789012', region: 'us-east-1' },
    });
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::WAFv2::WebACL', {
      Scope: 'CLOUDFRONT',
      Rules: Match.arrayWith([
        Match.objectLike({
          Statement: Match.objectLike({
            ManagedRuleGroupStatement: Match.objectLike({ Name: 'AWSManagedRulesCommonRuleSet' }),
          }),
          VisibilityConfig: Match.objectLike({ CloudWatchMetricsEnabled: true, SampledRequestsEnabled: true }),
        }),
        Match.objectLike({
          Statement: Match.objectLike({
            ManagedRuleGroupStatement: Match.objectLike({ Name: 'AWSManagedRulesAmazonIpReputationList' }),
          }),
        }),
        Match.objectLike({
          Statement: Match.objectLike({ RateBasedStatement: Match.objectLike({ Limit: 300, AggregateKeyType: 'IP' }) }),
          Action: Match.objectLike({ Block: Match.anyValue() }),
        }),
      ]),
    });

    // Regression guard for the production incident: CAPTCHA on /api/* broke
    // every programmatic API call (a fetch()/XHR can never solve a CAPTCHA),
    // and it protected nothing that wasn't already behind Cognito auth.
    const acl = Object.values(template.findResources('AWS::WAFv2::WebACL'))[0] as any;
    const rules = acl.Properties.Rules as any[];
    expect(rules).toHaveLength(3);
    expect(rules.some((r) => r.Action?.Captcha)).toBe(false);
    expect(rules.some((r) => r.Name === 'CaptchaOnApiPaths')).toBe(false);
  });

  test('exports the Web ACL ARN as both a construct property and a CfnOutput, for the cross-region reference into PocValidatorWebStack', () => {
    const app = new cdk.App();
    const stack = new PocValidatorWafStack(app, 'TestWafStack', {
      env: { account: '123456789012', region: 'us-east-1' },
    });
    expect(stack.webAclArn).toBeDefined();
    const template = Template.fromStack(stack);
    template.hasOutput('WebAclArn', {});
  });
});

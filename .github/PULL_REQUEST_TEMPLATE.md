**What this changes**

**Why**

**Verification**
- [ ] `python3 -m pytest tests/ -q` passes
- [ ] `npx jest` passes in the CDK directory
- [ ] `npx cdk synth --quiet` succeeds
- [ ] If this touches the UI, I deployed it and checked it in a browser
- [ ] No AWS account ID, ARN with an account ID, access key, or endpoint hostname added

**Determinism check**
- [ ] This change does not move a number, integration verdict, or citation URL
      from deterministic code into model output

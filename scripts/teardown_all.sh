#!/usr/bin/env bash
# Tear down every resource this project creates, in one or more regions.
#
#   ./scripts/teardown_all.sh us-east-1            # dry run: list what would be deleted
#   ./scripts/teardown_all.sh us-east-1 --confirm  # actually delete
#
# Deliberately refuses to delete anything unless --confirm is passed AND the
# operator types the region name back. Destruction is not a flag you fat-finger.
set -euo pipefail

REGION="${1:-}"
CONFIRM="${2:-}"

if [[ -z "$REGION" ]]; then
  echo "usage: $0 <region> [--confirm]" >&2
  exit 2
fi

WEB_STACK="PocValidatorWebStack"
WAF_STACK="PocValidatorWafStack"      # us-east-1 only (CloudFront-scope WAF)
AGENT_STACK="AgentCore-PocValidator-dev"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "Discovering resources in $REGION"

stack_exists() {
  aws cloudformation describe-stacks --stack-name "$1" --region "$2" >/dev/null 2>&1
}

FOUND=()
for s in "$WEB_STACK" "$AGENT_STACK"; do
  if stack_exists "$s" "$REGION"; then FOUND+=("$s ($REGION)"); fi
done
if stack_exists "$WAF_STACK" us-east-1; then FOUND+=("$WAF_STACK (us-east-1)"); fi

if [[ ${#FOUND[@]} -eq 0 ]]; then
  echo "No project stacks found in $REGION. Nothing to do."
  exit 0
fi

echo "Stacks that will be deleted:"
printf '  - %s\n' "${FOUND[@]}"

# Buckets and ECR repos survive stack deletion when non-empty; list them so the
# operator can see what the retained-resource sweep will touch.
say "Buckets matching this project in $REGION"
aws s3api list-buckets --region "$REGION" \
  --query "Buckets[?starts_with(Name,'poc-validator')].Name" --output text || true

say "ECR repositories matching this project in $REGION"
aws ecr describe-repositories --region "$REGION" \
  --query "repositories[?starts_with(repositoryName,'poc-validator') || contains(repositoryName,'pocvalidator')].repositoryName" \
  --output text 2>/dev/null || true

if [[ "$CONFIRM" != "--confirm" ]]; then
  say "DRY RUN"
  echo "Nothing was deleted. Re-run with --confirm to proceed:"
  echo "  $0 $REGION --confirm"
  exit 0
fi

say "CONFIRMATION REQUIRED"
echo "This permanently deletes the stacks listed above and their data"
echo "(DynamoDB tables, S3 site content, Cognito users, agent runtime)."
read -r -p "Type the region name ($REGION) to proceed: " TYPED
if [[ "$TYPED" != "$REGION" ]]; then
  echo "Input did not match. Aborted; nothing deleted."
  exit 1
fi

# Order matters: the web stack references the WAF stack and the agent runtime.
say "Deleting $WEB_STACK in $REGION"
stack_exists "$WEB_STACK" "$REGION" && \
  aws cloudformation delete-stack --stack-name "$WEB_STACK" --region "$REGION" && \
  aws cloudformation wait stack-delete-complete --stack-name "$WEB_STACK" --region "$REGION" || true

say "Deleting $AGENT_STACK in $REGION"
if stack_exists "$AGENT_STACK" "$REGION"; then
  if [[ -x ./destroy.sh ]]; then
    AWS_REGION="$REGION" ./destroy.sh dev || true
  else
    aws cloudformation delete-stack --stack-name "$AGENT_STACK" --region "$REGION" || true
    aws cloudformation wait stack-delete-complete --stack-name "$AGENT_STACK" --region "$REGION" || true
  fi
fi

say "Deleting $WAF_STACK in us-east-1"
stack_exists "$WAF_STACK" us-east-1 && \
  aws cloudformation delete-stack --stack-name "$WAF_STACK" --region us-east-1 && \
  aws cloudformation wait stack-delete-complete --stack-name "$WAF_STACK" --region us-east-1 || true

say "Cognito (M2M pool created outside CDK, if present)"
[[ -x ./scripts/teardown_cognito.sh ]] && ./scripts/teardown_cognito.sh || \
  echo "  (no teardown_cognito.sh; skipping)"

say "Retained resources sweep"
echo "CloudFormation retains non-empty buckets and ECR repos. Review and remove:"
aws s3api list-buckets --query "Buckets[?starts_with(Name,'poc-validator')].Name" --output text || true
echo "  aws s3 rb s3://<bucket> --force"
echo "  aws ecr delete-repository --repository-name <repo> --force --region $REGION"

say "Remaining project stacks in $REGION"
aws cloudformation list-stacks --region "$REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE ROLLBACK_COMPLETE \
  --query "StackSummaries[?contains(StackName,'PocValidator')].StackName" --output text || echo "  none"

say "Done"

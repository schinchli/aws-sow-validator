#!/usr/bin/env bash
# Fast front-end deploy: sync source/web to the live S3 bucket and invalidate
# CloudFront. Seconds, versus ~3.5 min for a full `cdk deploy`.
#
#   ./scripts/deploy_site.sh [region]
#
# Use this for HTML/CSS/JS/asset changes only. Anything that alters
# infrastructure (Lambda code, IAM, behaviors, WAF) still needs `cdk deploy`.
set -euo pipefail
REGION="${1:-us-east-1}"
STACK="PocValidatorWebStack"
SITE_DIR="$(cd "$(dirname "$0")/.." && pwd)/source/web"

[ -d "$SITE_DIR" ] || { echo "no such dir: $SITE_DIR" >&2; exit 1; }

BUCKET=$(aws cloudformation describe-stack-resources --stack-name "$STACK" --region "$REGION" \
  --query "StackResources[?ResourceType=='AWS::S3::Bucket'].PhysicalResourceId | [0]" --output text)
DIST=$(aws cloudformation describe-stack-resources --stack-name "$STACK" --region "$REGION" \
  --query "StackResources[?ResourceType=='AWS::CloudFront::Distribution'].PhysicalResourceId | [0]" --output text)

[ "$BUCKET" != "None" ] && [ -n "$BUCKET" ] || { echo "could not resolve site bucket" >&2; exit 1; }
echo "bucket:       $BUCKET"
echo "distribution: $DIST"

# --size-only is wrong for same-length edits; compare checksums instead.
# Never --delete: the Lambda writes share/*.json into this same bucket at
# runtime, and pruning would destroy live user data.
aws s3 sync "$SITE_DIR" "s3://$BUCKET/" \
  --exclude '.DS_Store' \
  --checksum-algorithm CRC32 \
  --cache-control 'no-cache, must-revalidate' \
  --region "$REGION"

# Explicit content types: S3 guesses, and a wrong type on .svg breaks rendering.
for f in "$SITE_DIR"/*.html; do
  [ -e "$f" ] || continue
  aws s3 cp "$f" "s3://$BUCKET/$(basename "$f")" \
    --content-type 'text/html; charset=utf-8' \
    --cache-control 'no-cache, must-revalidate' --region "$REGION" >/dev/null
done
if [ -f "$SITE_DIR/architecture.svg" ]; then
  aws s3 cp "$SITE_DIR/architecture.svg" "s3://$BUCKET/architecture.svg" \
    --content-type 'image/svg+xml' --region "$REGION" >/dev/null
fi

ID=$(aws cloudfront create-invalidation --distribution-id "$DIST" \
  --paths '/' '/index.html' '/architecture.svg' '/architecture.png' \
  --query 'Invalidation.Id' --output text)
echo "invalidation: $ID"
echo "done — https://$(aws cloudfront get-distribution --id "$DIST" --query 'Distribution.DomainName' --output text)/"

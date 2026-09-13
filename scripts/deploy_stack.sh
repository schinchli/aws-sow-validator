#!/usr/bin/env bash
# Full infrastructure deploy. Discovers the AgentCore runtime ARN itself, so no
# account-specific values need to be typed or committed.
#
#   ./scripts/deploy_stack.sh [region]
#
# For front-end-only changes use ./scripts/deploy_site.sh — it takes seconds.
set -euo pipefail
REGION="${1:-us-east-1}"
CDK_DIR="$(cd "$(dirname "$0")/.." && pwd)/infrastructure/cdk"
SELF_HOST_URL="${SELF_HOST_URL:-https://github.com/schinchli/aws-sow-validator}"
FREE_RUNS="${FREE_RUNS:-3}"

# Discover the agent runtime, if one exists. Absent = deterministic-only deploy,
# which is a valid configuration, not an error.
RUNTIME_ARN=$(python3 - "$REGION" <<'PY' 2>/dev/null || true
import sys, boto3
try:
    c = boto3.client("bedrock-agentcore-control", region_name=sys.argv[1])
    rts = c.list_agent_runtimes().get("agentRuntimes", [])
    print(rts[0]["agentRuntimeArn"] if rts else "")
except Exception:
    print("")
PY
)

CTX=(-c "selfHostUrl=$SELF_HOST_URL" -c "freeRuns=$FREE_RUNS")
if [ -n "${RUNTIME_ARN:-}" ]; then
  echo "agent runtime: found (Tier 2 / Amazon Nova enabled)"
  CTX+=(-c "agentRuntimeArn=$RUNTIME_ARN")
else
  echo "agent runtime: none found — deploying Tier 1 (deterministic) only"
fi

cd "$CDK_DIR"

# Use the LOCAL CDK CLI, not `npx cdk`. npx can resolve to a globally installed
# cdk (e.g. Homebrew) whose behaviour differs and which silently produced no
# cloud assembly here. The pinned local version is the one the tests run against.
CDK_BIN="./node_modules/.bin/cdk"
[ -x "$CDK_BIN" ] || { echo "CDK CLI missing - run 'npm ci' in $CDK_DIR" >&2; exit 1; }

# cdk.json runs the COMPILED app (node dist/bin/web.js), so stale dist/ means
# deploying yesterday's infrastructure. Always rebuild first.
npm run build >/dev/null

echo "deploying to $REGION ..."
"$CDK_BIN" deploy PocValidatorWafStack PocValidatorWebStack \
  --require-approval never --concurrency 1 "${CTX[@]}"

"""poc-validator-web-invoke — Lambda proxy in front of the AgentCore Runtime.

Handles the following routes, all reached via CloudFront on the same domain
as the page itself. The site is public self-service: /api/invoke and
/api/drive/* require a Cognito ID token (X-Id-Token header) —
see _authenticate/_verify_jwt — instead of the old edge Basic Auth.
  POST /api/invoke          — runs the agent (or the deterministic Tier 1
                               engine). Requires auth. Each verified user
                               gets FREE_RUNS agent reviews on this hosted
                               instance, then 402 quota_exhausted pointing
                               at SELF_HOST_URL — deploy your own copy
                               instead of asking for more quota. The
                               deterministic tier is unmetered.
  GET  /api/me               — the caller's quota status.
  GET  /share/<id>.json      — serves a previously-completed result,
                               publicly, no auth required — but capped at 3
                               views and 30 days via a DynamoDB counter,
                               enforced here rather than trusted to the
                               client.
  GET  /api/drive/list        — lists .docx SOWs in a Google Drive folder
                               shared with a service account (optional
                               feature: returns a clean "not configured"
                               error until the secret and folder id are
                               provisioned). Requires auth.
  GET  /api/drive/fetch       — downloads one Drive file and returns its
                               extracted text (server-side, stdlib-only
                               .docx parsing), so the browser never handles
                               multi-MB binaries. Requires auth.
"""

import hashlib
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

import boto3
import jwt
from botocore.exceptions import ClientError
from jwt import PyJWKClient

from allowlist import is_signup_allowed
from sse import _extract_trailing_json, _reassemble_sse  # noqa: F401 — re-exported for tests

# Optional: empty means this deployment has no AgentCore runtime wired up
# (a one-click/no-Bedrock-access install) — mode="agent" then answers a
# clean 503 instead of crashing on an empty ARN, and Tier 1 (deterministic)
# remains fully available.
RUNTIME_ARN = os.environ.get("AGENT_RUNTIME_ARN", "")
# Vestigial: the Basic-Auth-era shared secret. No longer gates any route —
# Cognito JWT + quota (below) is the real access control now that the site
# is public self-service — but still required from the environment since
# the CDK stack still wires demoKey through for now.
EXPECTED_KEY = os.environ["DEMO_KEY"]
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
RESULTS_BUCKET = os.environ["RESULTS_BUCKET"]
PUBLIC_BASE_URL = os.environ["PUBLIC_BASE_URL"]
VIEWS_TABLE = os.environ["VIEWS_TABLE"]

# ---- End-user auth (Cognito) + quota -------------------------------------
USER_POOL_ID = os.environ["USER_POOL_ID"]
USER_POOL_CLIENT_ID = os.environ["USER_POOL_CLIENT_ID"]
USERS_TABLE = os.environ["USERS_TABLE"]
FREE_RUNS = int(os.environ.get("FREE_RUNS", "1"))
# Where a user hits their quota is told to deploy their own copy instead of
# asking for more free runs — no payment/credit-granting path exists.
SELF_HOST_URL = os.environ.get(
    "SELF_HOST_URL", "https://github.com/awslabs/agentcore-samples")
MAX_DOCUMENT_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", "5242880"))  # 5 MB cap on sow_text + diagram_text

# ---- Sign-up allowlist, checked here too as defence in depth -------------
# The Cognito PreSignUp trigger (source/api/presignup.py) is the authoritative
# gate on account creation; this is a second check on every API call so a
# reconfigured/misconfigured user pool can't silently bypass the policy.
# Same env var, same matching rule — see allowlist.py. Empty allows everyone.
SIGNUP_ALLOWED = os.environ.get("SIGNUP_ALLOWED", "")

MAX_VIEWS = 3
SHARE_TTL_SECONDS = 30 * 24 * 3600

# Must stay in lockstep with the <select> options in source/web/index.html
# and the rule packs the runtime actually ships.
ALLOWED_SEGMENTS = {"enterprise", "smb", "digital_native"}
ALLOWED_INDUSTRIES = {"generic", "fsi", "retail"}
ALLOWED_MODES = {"agent", "deterministic"}

# Tier 1 needs pocvalidator.core + config/data/ bundled by the CDK *local* bundler.
# Import lazily so a Docker-bundled deploy (which can't reach outside the
# asset dir) degrades to agent-only instead of failing every request.
try:
    import tier1 as _tier1
except ImportError:  # pragma: no cover — bundling gap, agent path still works
    _tier1 = None

CACHE_PREFIX = "cache/"

# The site's confidential banned-brand list, uploaded out-of-band to the
# config/ prefix (never committed). Cached in the execution environment.
_banned_cache = {"value": None}


def _banned_brands():
    if _banned_cache["value"] is None:
        try:
            obj = _s3.get_object(Bucket=RESULTS_BUCKET, Key="config/banned-clients.json")
            _banned_cache["value"] = json.loads(obj["Body"].read()).get("banned", [])
        except Exception:  # noqa: BLE001 — missing config just disables the check
            _banned_cache["value"] = []
    return _banned_cache["value"]


def _cache_key(payload):
    canonical = json.dumps(
        {k: payload.get(k) for k in (
            "mode", "sow_text", "diagram_text", "segment", "industry", "region",
            "services", "edges", "extraction_confirmed")},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _cache_get(key):
    try:
        obj = _s3.get_object(Bucket=RESULTS_BUCKET, Key=f"{CACHE_PREFIX}{key}.json")
        return json.loads(obj["Body"].read())
    except Exception:  # noqa: BLE001 — any miss/error means "not cached"
        return None


def _cache_put(key, result):
    try:
        _s3.put_object(
            Bucket=RESULTS_BUCKET, Key=f"{CACHE_PREFIX}{key}.json",
            Body=json.dumps(result).encode(), ContentType="application/json")
    except Exception:  # noqa: BLE001 — caching is best-effort, never blocks
        pass

# Google Drive integration is OPTIONAL: both values empty means the /api/drive
# routes answer with a clear "not configured" error and nothing else changes.
DRIVE_SA_SECRET_ARN = os.environ.get("DRIVE_SA_SECRET_ARN", "")
DRIVE_FOLDER_ID = os.environ.get("DRIVE_FOLDER_ID", "")
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
GDOC_MIME = "application/vnd.google-apps.document"
MAX_DRIVE_BYTES = 30 * 1024 * 1024

_region = os.environ.get("AWS_REGION", "us-east-1")
_client = boto3.client("bedrock-agentcore", region_name=_region)
_s3 = boto3.client("s3", region_name=_region)
_views_table = boto3.resource("dynamodb", region_name=_region).Table(VIEWS_TABLE)
_users_table = boto3.resource("dynamodb", region_name=_region).Table(USERS_TABLE)

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, x-demo-key, authorization",
}

# ---------------------------------------------------------------------------
# Cognito ID token verification.
# ---------------------------------------------------------------------------
# PyJWKClient fetches https://cognito-idp.<region>.amazonaws.com/<poolId>/
# .well-known/jwks.json over stdlib urllib and caches the parsed keys itself
# (module-level instance == the cache); no extra HTTP dependency needed.
COGNITO_ISSUER = f"https://cognito-idp.{_region}.amazonaws.com/{USER_POOL_ID}"
_JWKS_URL = f"{COGNITO_ISSUER}/.well-known/jwks.json"
_jwks_client = PyJWKClient(_JWKS_URL, cache_keys=True)


class AuthError(Exception):
    """Any reason a request is not from a verified, signed-in user.

    Always surfaced as HTTP 401 with a machine-readable `code` so the
    frontend can react (re-login vs. "verify your email" vs. generic retry).
    """

    def __init__(self, code, message, status=401):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _verify_jwt(token):
    """Verify a Cognito ID token: RS256 signature, iss, aud == client id,
    exp, and email_verified == true. Returns the decoded claims on success;
    raises AuthError on any failure. Never guesses — every check is explicit."""
    if not token:
        raise AuthError("missing_token", "Missing bearer token.")
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
    except jwt.exceptions.PyJWKClientError as exc:
        raise AuthError("invalid_token", f"Unable to resolve signing key: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — malformed token, not a server error
        raise AuthError("invalid_token", f"Malformed token: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=USER_POOL_CLIENT_ID,
            issuer=COGNITO_ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("token_expired", "Token has expired.") from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthError("invalid_audience", "Token was not issued for this app client.") from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthError("invalid_issuer", "Token was not issued by the expected user pool.") from exc
    except jwt.PyJWTError as exc:
        raise AuthError("invalid_token", f"Invalid token: {exc}") from exc

    if claims.get("token_use") != "id":
        raise AuthError("invalid_token_use", "Expected a Cognito ID token, not an access token.")
    if not claims.get("email_verified"):
        raise AuthError("email_not_verified", "Email address has not been verified.")
    if not is_signup_allowed(claims.get("email", ""), SIGNUP_ALLOWED):
        raise AuthError(
            "email_not_allowed",
            "This hosted instance is restricted to an allowlist of email "
            f"addresses. Fork the repository and deploy your own copy into "
            f"your own AWS account: {SELF_HOST_URL}",
            status=403,
        )
    return claims


def _authenticate(event):
    """Extract + verify the bearer token. Returns (claims, None) on success
    or (None, error_response) on failure — callers just check the second
    element before proceeding."""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    # CloudFront Origin Access Control with SigningBehavior=always REPLACES the
    # viewer's Authorization header with its own SigV4 signature, so a Cognito
    # ID token sent as "Authorization: Bearer ..." never reaches this function.
    # The browser therefore sends it as X-Id-Token, which CloudFront forwards
    # untouched. Authorization is kept as a fallback for direct invocations
    # (tests, curl against the Function URL) that do not traverse CloudFront.
    token = (headers.get("x-id-token") or "").strip()
    if not token:
        auth_header = headers.get("authorization") or ""
        token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    try:
        claims = _verify_jwt(token)
    except AuthError as exc:
        # Log the reason: a 401 that returns in 2 ms with no log line is
        # undiagnosable from CloudWatch, and the caller only sees "rejected".
        print(f"[auth] rejected: code={exc.code} reason={exc.message}")
        return None, _response(exc.status, {"status": "error", "code": exc.code, "message": exc.message})
    return claims, None


def _ensure_user_record(user_sub, email):
    """Idempotently create the user's quota row on first sight, so the
    conditional UpdateItem below always has an item to update."""
    try:
        _users_table.put_item(
            Item={
                "user_sub": user_sub,
                "email": email,
                "runs_used": 0,
                "created_at": int(time.time()),
                "last_run_at": 0,
            },
            ConditionExpression="attribute_not_exists(user_sub)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise


def _consume_free_run(user_sub, email):
    """Atomically claim one of the caller's FREE_RUNS hosted-agent reviews —
    no purchasable credits, no payment path. Same conditional-UpdateItem
    pattern as the existing share-view counter (_check_and_increment_view).
    Once exhausted the answer is "deploy your own copy", not "buy more"."""
    _ensure_user_record(user_sub, email)
    try:
        resp = _users_table.update_item(
            Key={"user_sub": user_sub},
            UpdateExpression="ADD runs_used :incr SET last_run_at = :now",
            ConditionExpression="runs_used < :limit",
            ExpressionAttributeValues={":incr": 1, ":now": int(time.time()), ":limit": FREE_RUNS},
            ReturnValues="UPDATED_NEW",
        )
        return {"ok": True, "runs_used": int(resp["Attributes"]["runs_used"])}
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        existing = _users_table.get_item(Key={"user_sub": user_sub}).get("Item") or {}
        return {"ok": False, "runs_used": int(existing.get("runs_used", FREE_RUNS))}


def _response(status, body_obj):
    return {
        "statusCode": status,
        "headers": {**_CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps(body_obj),
    }


def _maybe_share(parsed):
    """Mint a view-limited share link for any complete result (agent,
    deterministic, or cache hit). The result never echoes the raw SOW/diagram
    text back — only the analysis — so the public share/ prefix stays safe."""
    if parsed.get("status") != "complete":
        return
    run_id = uuid.uuid4().hex
    expires_at = int(time.time()) + SHARE_TTL_SECONDS
    try:
        _s3.put_object(
            Bucket=RESULTS_BUCKET,
            Key=f"share/{run_id}.json",
            Body=json.dumps(parsed).encode("utf-8"),
            ContentType="application/json",
            CacheControl="no-store",  # view-count enforcement needs every read to hit the Lambda
            Tagging="AutoExpire=true",
        )
        _views_table.put_item(Item={"share_id": run_id, "view_count": 0, "ttl": expires_at})
        parsed["share_url"] = f"{PUBLIC_BASE_URL}/share/view.html?id={run_id}"
    except Exception as exc:  # noqa: BLE001 — sharing is a bonus, never block the result on it
        parsed["share_url"] = None
        parsed["share_error"] = str(exc)


def _handle_invoke(event, claims):
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"status": "error", "message": "Body must be JSON."})

    sow_text = (body.get("sow_text") or "").strip()
    diagram_text = body.get("diagram_text") or ""

    # MAX_DOCUMENT_BYTES cap on the actual document content, enforced
    # server-side regardless of what the client claims it sent.
    doc_bytes = len(sow_text.encode("utf-8")) + len(diagram_text.encode("utf-8"))
    if doc_bytes > MAX_DOCUMENT_BYTES:
        return _response(413, {"error": "file_too_large", "limit_bytes": MAX_DOCUMENT_BYTES})

    diagram_filename = body.get("diagram_filename") or "diagram.mmd"
    segment = body.get("segment") or "enterprise"
    industry = body.get("industry") or "generic"
    region = body.get("region") or "us-east-1"

    # Mirror the page's dropdowns exactly — anything else reaches the rule-pack
    # lookup inside the runtime and dies mid-stream as a KeyError, which the
    # browser only ever sees as an opaque 502.
    if segment not in ALLOWED_SEGMENTS:
        return _response(400, {"status": "error", "message": f"Unknown segment {segment!r}. Allowed: {sorted(ALLOWED_SEGMENTS)}."})
    if industry not in ALLOWED_INDUSTRIES:
        return _response(400, {"status": "error", "message": f"Unknown industry {industry!r}. Allowed: {sorted(ALLOWED_INDUSTRIES)}."})
    mode = body.get("mode") or "agent"
    if mode not in ALLOWED_MODES:
        return _response(400, {"status": "error", "message": f"Unknown mode {mode!r}. Allowed: {sorted(ALLOWED_MODES)}."})

    if mode == "agent" and not RUNTIME_ARN:
        return _response(503, {
            "status": "error", "code": "agent_not_configured",
            "message": "This deployment has no AgentCore runtime configured — use mode=\"deterministic\".",
        })

    # Quota: FREE_RUNS hosted agent reviews per verified user, no purchasable
    # credits — exhausting it means "deploy your own copy", not "buy more".
    # Deterministic (Tier 1) is zero model cost and stays free for any
    # signed-in verified user — only the agent/Nova path is metered.
    # Charged before the cache lookup below: the user asked for an agent
    # review, which is their metered action regardless of whether the
    # answer happens to be served from cache.
    if mode == "agent":
        quota = _consume_free_run(claims["sub"], claims.get("email", ""))
        if not quota["ok"]:
            return _response(402, {
                "error": "quota_exhausted",
                "runs_used": quota["runs_used"],
                "free_runs": FREE_RUNS,
                "self_host_url": SELF_HOST_URL,
                "message": "Free hosted reviews are limited. Deploy your own copy in your "
                           "AWS account — one command, no quota.",
            })

    # Confirmation round-trip fields (the SOW/vision extraction gate): the
    # browser echoes back the extracted services/edges it confirmed. Validated
    # structurally here; the agent's catalogue resolution rejects unknown ids.
    services = body.get("services") or []
    if not (
        isinstance(services, list)
        and len(services) <= 50
        and all(isinstance(s, str) and len(s) <= 64 for s in services)
    ):
        services = []
    edges = body.get("edges") or []
    if not (
        isinstance(edges, list)
        and len(edges) <= 200
        and all(
            isinstance(e, list)
            and len(e) == 2
            and all(isinstance(x, str) and len(x) <= 64 for x in e)
            for e in edges
        )
    ):
        edges = []
    extraction_confirmed = bool(body.get("extraction_confirmed"))

    if not sow_text and not diagram_text and not services:
        return _response(400, {"status": "error", "message": "Provide at least an SOW document or a diagram."})

    # A stable per-browser id (generated client-side, kept in localStorage) so
    # AgentCore Memory's USER_PREFERENCE strategy has a real, consistent actor
    # to attach preferences to instead of every visitor sharing one identity.
    # Validated strictly — this becomes part of a Memory namespace string.
    browser_id = body.get("browser_id") or ""
    if not re.fullmatch(r"[a-f0-9]{32}", browser_id):
        browser_id = "anonymous"

    payload = {
        "segment": segment,
        "industry": industry,
        "region": region,
        "sow_text": sow_text,
        "diagram_text": diagram_text,
        "diagram_filename": diagram_filename,
        "services": services,
        "edges": edges,
        "extraction_confirmed": extraction_confirmed,
        "user_id": f"web-{browser_id}",
    }
    # SOW text evidence → per-service attribute overrides, so the rule packs
    # judge what the document actually states instead of bare defaults. The
    # runtime already honours config_overrides; this fixes the agent path
    # without touching the container.
    evidence_applied = []
    if _tier1 is not None and sow_text and services:
        payload["config_overrides"], evidence_applied = _tier1.attribute_overrides(sow_text, services)

    # Identical inputs → identical review. Serve the stored answer: zero model
    # tokens, zero agent seconds. share_url is per-run so it is never cached.
    cache_key = _cache_key({**payload, "mode": mode})
    cached = _cache_get(cache_key)
    if cached is not None:
        cached["cached"] = True
        _maybe_share(cached)  # a fresh share link per serve; the result itself cost nothing
        return _response(200, cached)

    if mode == "deterministic":
        if _tier1 is None:
            return _response(503, {"status": "error", "message": "Deterministic tier not bundled in this deployment — use the agent review."})
        payload["client_name"] = body.get("client_name") or ""
        result = _tier1.run(payload, _banned_brands())
        _cache_put(cache_key, result)
        _maybe_share(result)
        return _response(200, result)

    try:
        result = _client.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN,
            runtimeSessionId=f"web-{uuid.uuid4().hex}",
            payload=json.dumps(payload).encode("utf-8"),
            contentType="application/json",
            accept="application/json",
        )
        raw = result["response"].read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — surface any failure as a clean JSON error
        return _response(502, {"status": "error", "message": f"Agent invocation failed: {exc}"})

    parsed = _extract_trailing_json(raw)
    if parsed is None:
        return _response(502, {"status": "error", "message": "Could not parse agent response.", "raw_tail": raw[-2000:]})

    # The runtime reports a mid-stream crash as a final {"error": ..., "message":
    # ...} event — surface its message instead of an unexplained 502.
    if "error" in parsed and "status" not in parsed:
        detail = parsed.get("error") or parsed.get("message") or "unknown"
        return _response(502, {"status": "error", "message": f"Agent runtime error: {detail}"})

    if _tier1 is not None:
        # Model extraction can fail outright (token-limit repetition loops on
        # long documents) — fall back to grounded deterministic detection so
        # the user still gets a confirmable service list instead of an error.
        extraction_failed = (
            parsed.get("status") == "error" and "extracted" in (parsed.get("message") or "")
        ) or (
            parsed.get("status") == "awaiting_confirmation"
            and not (parsed.get("extraction") or {}).get("services")
        )
        if extraction_failed and sow_text and not extraction_confirmed:
            detected, grounding = _tier1.detect_services(sow_text)
            if detected:
                parsed = {"status": "awaiting_confirmation", "extraction": {
                    "services": detected, "edges": [], "unmatched": [],
                    "grounding": grounding,
                    "notes": "Model extraction failed — these services come from "
                             "deterministic text search (every one has document evidence).",
                }}

        # Grounding + lenses + applied evidence are deterministic decorations
        # on the agent's answer.
        if parsed.get("status") == "awaiting_confirmation" and parsed.get("extraction"):
            parsed["extraction"] = _tier1.ground_extraction(parsed["extraction"], sow_text)
        elif parsed.get("status") == "complete":
            parsed.setdefault("tier", "agent")
            parsed.setdefault("lenses", _tier1.select_lenses(industry, services, sow_text))
            parsed.setdefault("evidence_applied", evidence_applied)
        _cache_put(cache_key, parsed)

    _maybe_share(parsed)

    return _response(200, parsed)


def _handle_me(claims):
    user_sub = claims["sub"]
    item = _users_table.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    return _response(200, {
        "email": claims.get("email", ""),
        "runs_used": int(item.get("runs_used", 0)),
        "free_runs": FREE_RUNS,
    })


def _check_and_increment_view(share_id):
    """Atomically claim one of the 3 allowed views. Returns a dict describing
    the outcome so the caller can give a precise error rather than a generic
    403 — worth doing since "never existed" and "viewed out" are different
    situations for someone clicking a stale link.
    """
    try:
        resp = _views_table.update_item(
            Key={"share_id": share_id},
            UpdateExpression="ADD view_count :incr",
            ConditionExpression="attribute_exists(share_id) AND view_count < :max",
            ExpressionAttributeValues={":incr": 1, ":max": MAX_VIEWS},
            ReturnValues="UPDATED_NEW",
        )
        return {"ok": True, "view_count": int(resp["Attributes"]["view_count"])}
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        existing = _views_table.get_item(Key={"share_id": share_id}).get("Item")
        return {"ok": False, "reason": "not_found" if existing is None else "limit_reached"}


def _handle_share_read(share_id):
    if not re.fullmatch(r"[a-f0-9]{32}", share_id or ""):
        return _response(404, {"status": "error", "message": "Not a valid share link."})

    outcome = _check_and_increment_view(share_id)
    if not outcome["ok"]:
        if outcome["reason"] == "not_found":
            return _response(404, {"status": "error", "message": "This link has expired or never existed."})
        return _response(403, {"status": "error", "message": "This shared result has already been viewed the maximum of 3 times."})

    try:
        obj = _s3.get_object(Bucket=RESULTS_BUCKET, Key=f"share/{share_id}.json")
        data = json.loads(obj["Body"].read())
    except ClientError:
        return _response(404, {"status": "error", "message": "This link has expired or never existed."})

    data["_views_remaining"] = MAX_VIEWS - outcome["view_count"]
    return _response(200, data)


_drive_token_cache = {"token": "", "expires": 0.0}


def _drive_token():
    """Access token for the Drive service account, cached until near expiry.

    The SA key never leaves Secrets Manager except into this process; the
    browser only ever sees extracted text.
    """
    if _drive_token_cache["token"] and time.time() < _drive_token_cache["expires"] - 60:
        return _drive_token_cache["token"]
    secret = boto3.client("secretsmanager", region_name=_region).get_secret_value(
        SecretId=DRIVE_SA_SECRET_ARN
    )["SecretString"]
    info = json.loads(secret)
    # google-auth (pure-python deps) builds the signed JWT; the token exchange
    # itself is one stdlib HTTP POST, so no HTTP transport extra is needed.
    from google.auth import jwt as google_jwt  # noqa: PLC0415 — import deferred so the route degrades cleanly if the dep is missing
    from google.auth.crypt import RSASigner  # noqa: PLC0415

    now = int(time.time())
    signer = RSASigner.from_service_account_info(info)
    assertion = google_jwt.encode(
        signer,
        {
            "iss": info["client_email"],
            "scope": "https://www.googleapis.com/auth/drive.readonly",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        },
    )
    body = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion.decode() if isinstance(assertion, bytes) else assertion,
        }
    ).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        tok = json.loads(resp.read())
    _drive_token_cache["token"] = tok["access_token"]
    _drive_token_cache["expires"] = time.time() + int(tok.get("expires_in", 3600))
    return _drive_token_cache["token"]


def _drive_get(url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {_drive_token()}"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read(MAX_DRIVE_BYTES + 1)


def _docx_to_text(data: bytes) -> str:
    """Stdlib .docx extraction, mirroring the browser parser: cell paragraphs
    join with spaces, cells with ' | ', rows and body paragraphs with newlines.
    No python-docx — its lxml dependency ships a native wheel the host-pip
    Lambda bundling cannot provide."""

    def convert(xml: str, p_sep: str) -> str:
        xml = re.sub(r"<w:tab[^>]*/>", "\t", xml)
        xml = xml.replace("</w:p>", p_sep)
        xml = xml.replace("</w:tc>", " | ").replace("</w:tr>", "\n")
        return xml

    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        parts = ["word/document.xml"] + sorted(
            n for n in zf.namelist() if re.fullmatch(r"word/(header|footer)\d*\.xml", n)
        )
        for name in parts:
            try:
                xml = zf.read(name).decode("utf-8", errors="replace")
            except KeyError:
                continue
            xml = re.sub(r"<w:tbl\b[\s\S]*?</w:tbl>", lambda m: convert(m.group(0), " "), xml)
            xml = convert(xml, "\n")
            xml = re.sub(r"<[^>]+>", "", xml)
            xml = (
                xml.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", '"').replace("&apos;", "'")
            )
            out.append(
                "\n".join(
                    re.sub(r"\s+\|", " |", re.sub(r"\|\s+", "| ", line)).rstrip(" |").strip()
                    for line in xml.splitlines()
                    if line.strip()
                )
            )
    return "\n".join(out)


def _handle_drive_list(event, claims):  # noqa: ARG001 — claims proves the caller authenticated; route has no per-user logic
    if not (DRIVE_SA_SECRET_ARN and DRIVE_FOLDER_ID):
        return _response(
            501,
            {"status": "error", "code": "drive_not_configured",
             "message": "Google Drive is not configured. See source/api/README-drive.md."},
        )
    try:
        q = urllib.parse.quote(
            f"'{DRIVE_FOLDER_ID}' in parents and trashed=false "
            f"and (mimeType='{DOCX_MIME}' or mimeType='{GDOC_MIME}')"
        )
        raw = _drive_get(
            "https://www.googleapis.com/drive/v3/files"
            f"?q={q}&fields=files(id,name,mimeType,modifiedTime,size)&pageSize=100"
            "&supportsAllDrives=true&includeItemsFromAllDrives=true"
        )
        files = json.loads(raw).get("files", [])
        return _response(200, {"status": "ok", "files": files})
    except Exception as exc:  # noqa: BLE001 — every Drive failure surfaces as clean JSON
        return _response(502, {"status": "error", "message": f"Drive list failed: {exc}"})


def _handle_drive_fetch(event, claims):  # noqa: ARG001 — claims proves the caller authenticated; route has no per-user logic
    if not (DRIVE_SA_SECRET_ARN and DRIVE_FOLDER_ID):
        return _response(
            501,
            {"status": "error", "code": "drive_not_configured",
             "message": "Google Drive is not configured. See source/api/README-drive.md."},
        )
    file_id = (event.get("queryStringParameters") or {}).get("id", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", file_id):
        return _response(400, {"status": "error", "message": "Invalid file id."})
    try:
        meta = json.loads(
            _drive_get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}"
                "?fields=id,name,mimeType,parents&supportsAllDrives=true"
            )
        )
        # The service account can see anything shared with it; only serve
        # files that actually live in the configured folder.
        if DRIVE_FOLDER_ID not in (meta.get("parents") or []):
            return _response(403, {"status": "error", "message": "File is outside the configured folder."})
        if meta.get("mimeType") == GDOC_MIME:
            data = _drive_get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}/export"
                f"?mimeType={urllib.parse.quote(DOCX_MIME)}"
            )
        else:
            data = _drive_get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&supportsAllDrives=true"
            )
        if len(data) > MAX_DRIVE_BYTES:
            return _response(413, {"status": "error", "message": "File exceeds the 30 MB limit."})
        text = _docx_to_text(data)
        return _response(200, {"status": "ok", "name": meta.get("name", ""), "chars": len(text), "text": text})
    except Exception as exc:  # noqa: BLE001 — every Drive failure surfaces as clean JSON
        return _response(502, {"status": "error", "message": f"Drive fetch failed: {exc}"})


def handler(event, context):
    method = (event.get("requestContext", {}).get("http", {}) or {}).get("method", "")
    path = event.get("rawPath") or (event.get("requestContext", {}).get("http", {}) or {}).get("path", "")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _CORS_HEADERS, "body": ""}

    # Public, unauthenticated: the view-limited share reads.
    share_match = re.fullmatch(r"/share/([a-f0-9]{32})\.json", path)
    if method == "GET" and share_match:
        return _handle_share_read(share_match.group(1))

    # Everything else here requires a verified Cognito ID token.
    if (
        (method == "GET" and path in ("/api/drive/list", "/api/drive/fetch", "/api/me"))
        or (method == "POST" and path == "/api/invoke")
    ):
        claims, err = _authenticate(event)
        if err:
            return err
        if path == "/api/drive/list":
            return _handle_drive_list(event, claims)
        if path == "/api/drive/fetch":
            return _handle_drive_fetch(event, claims)
        if path == "/api/me":
            return _handle_me(claims)
        return _handle_invoke(event, claims)

    return _response(404, {"status": "error", "message": "Not found."})

"""poc-validator-gmail-poller — AWS-native, event-driven email reviews.

No schedules, no polling: the owner sends the SOW email, then pings
GET /api/gmail/check (CloudFront route, Basic Auth at the edge) — that single
request invokes this handler, which reads the mailbox once (Gmail REST API —
OAuth refresh token held in Secrets Manager, the only Google-side artifact)
for mail sent BY the owner to the +sow alias, then:

  new SOW (has attachment)   → immediate "received, processing" reply
                             → Tier 1 deterministic review in-process
                             → full report reply; context saved for chat
  follow-up in a reviewed    → question answered by the AgentCore runtime
  thread (no attachment)       (what-if pricing / FAQ search) using the
                               thread's saved services/edges context

Everything except mailbox access runs on real AWS credentials (the Lambda
role): S3 for config/state, bedrock-agentcore for chat, Secrets Manager for
the Gmail token. No demo key, no Basic Auth, no Apps Script.

Security: only messages FROM the owner are processed — the poller never
reacts to third-party mail, and its own sent replies are labelled processed
the moment they are sent so they can never re-trigger it.
"""

import base64
import json
import os
import re
import urllib.parse
import urllib.request
import zipfile
from email.message import EmailMessage
from io import BytesIO

import boto3

import tier1
from sse import _extract_trailing_json

_region = os.environ.get("AWS_REGION", "us-east-1")
_s3 = boto3.client("s3", region_name=_region)
_secrets = boto3.client("secretsmanager", region_name=_region)
_agent = boto3.client("bedrock-agentcore", region_name=_region)

GMAIL_SECRET_ARN = os.environ["GMAIL_SECRET_ARN"]
OWNER = os.environ["OWNER_EMAIL"].lower()
ALIAS = os.environ["ALIAS_EMAIL"].lower()
CONFIG_BUCKET = os.environ["CONFIG_BUCKET"]
RUNTIME_ARN = os.environ.get("AGENT_RUNTIME_ARN", "")
LABEL = "sow-processed"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024

_token_cache = {"value": None}
_label_cache = {"value": None}
_banned_cache = {"value": None}


# ---------------------------------------------------------------------------
# Gmail REST client (urllib only — no Google SDK needed)
# ---------------------------------------------------------------------------


def _http(url, data=None, token=None, method=None):
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"))
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"{}")


def _access_token():
    if _token_cache["value"] is None:
        creds = json.loads(
            _secrets.get_secret_value(SecretId=GMAIL_SECRET_ARN)["SecretString"])
        body = urllib.parse.urlencode({
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": creds["refresh_token"],
            "grant_type": "refresh_token",
        }).encode()
        req = urllib.request.Request("https://oauth2.googleapis.com/token", data=body)
        with urllib.request.urlopen(req, timeout=30) as resp:
            _token_cache["value"] = json.loads(resp.read())["access_token"]
    return _token_cache["value"]


def _label_id(token):
    if _label_cache["value"] is None:
        labels = _http(f"{GMAIL}/labels", token=token).get("labels", [])
        for label in labels:
            if label["name"] == LABEL:
                _label_cache["value"] = label["id"]
                break
        else:
            created = _http(f"{GMAIL}/labels", token=token,
                            data=json.dumps({"name": LABEL}).encode())
            _label_cache["value"] = created["id"]
    return _label_cache["value"]


def _mark_processed(token, message_id):
    _http(f"{GMAIL}/messages/{message_id}/modify", token=token,
          data=json.dumps({"addLabelIds": [_label_id(token)]}).encode())


def _send_reply(token, thread, text):
    msg = EmailMessage()
    msg["To"] = OWNER
    msg["From"] = OWNER
    msg["Subject"] = ("Re: " + thread["subject"]) if not thread["subject"].lower().startswith("re:") else thread["subject"]
    if thread.get("message_id_header"):
        msg["In-Reply-To"] = thread["message_id_header"]
        msg["References"] = thread["message_id_header"]
    msg.set_content(text)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    sent = _http(f"{GMAIL}/messages/send", token=token,
                 data=json.dumps({"raw": raw, "threadId": thread["thread_id"]}).encode())
    # Our own replies match the poll query (from:owner, subject SOW) — label
    # them processed immediately so they can never re-trigger the poller.
    _mark_processed(token, sent["id"])


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------


def _header(payload, name):
    for h in payload.get("headers", []):
        if h["name"].lower() == name.lower():
            return h["value"]
    return ""


def _walk_parts(payload):
    stack = [payload]
    while stack:
        part = stack.pop()
        yield part
        stack.extend(part.get("parts", []))


def _plain_body(payload):
    for part in _walk_parts(payload):
        if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
            return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", "ignore")
    return ""


def strip_quoted(text):
    """Keep only the new content of a reply — drop quoted history."""
    lines = []
    for line in text.splitlines():
        if line.startswith(">") or re.match(r"^On .{6,80} wrote:\s*$", line):
            break
        lines.append(line)
    return "\n".join(lines).strip()


def _docx_to_text(data):
    with zipfile.ZipFile(BytesIO(data)) as zf:
        xml = zf.read("word/document.xml").decode("utf-8", "ignore")
    xml = re.sub(r"</w:p>", "\n", xml)
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"<[^>]+>", "", xml)).strip()


def _attachment_text(token, message_id, payload):
    for part in _walk_parts(payload):
        filename = (part.get("filename") or "").lower()
        body = part.get("body", {})
        if not filename or not body.get("attachmentId"):
            continue
        if body.get("size", 0) > MAX_ATTACHMENT_BYTES:
            continue
        if filename.endswith((".docx", ".txt", ".md")):
            att = _http(f"{GMAIL}/messages/{message_id}/attachments/{body['attachmentId']}",
                        token=token)
            data = base64.urlsafe_b64decode(att["data"])
            if filename.endswith(".docx"):
                try:
                    return part["filename"], _docx_to_text(data)
                except Exception:  # noqa: BLE001 — malformed docx, keep looking
                    continue
            return part["filename"], data.decode("utf-8", "ignore")
    return None, None


# ---------------------------------------------------------------------------
# Review + chat
# ---------------------------------------------------------------------------


def _banned_brands():
    if _banned_cache["value"] is None:
        try:
            obj = _s3.get_object(Bucket=CONFIG_BUCKET, Key="config/banned-clients.json")
            _banned_cache["value"] = json.loads(obj["Body"].read()).get("banned", [])
        except Exception:  # noqa: BLE001
            _banned_cache["value"] = []
    return _banned_cache["value"]


def _ctx_key(thread_id):
    return f"gmail-state/ctx/{thread_id}.json"


def _save_ctx(thread_id, ctx):
    _s3.put_object(Bucket=CONFIG_BUCKET, Key=_ctx_key(thread_id),
                   Body=json.dumps(ctx).encode(), ContentType="application/json")


def _load_ctx(thread_id):
    try:
        obj = _s3.get_object(Bucket=CONFIG_BUCKET, Key=_ctx_key(thread_id))
        return json.loads(obj["Body"].read())
    except Exception:  # noqa: BLE001 — no context: thread was never reviewed
        return None


def _options_from_subject(subject):
    s = subject.lower()
    segment = ("enterprise" if "enterprise" in s
               else "digital_native" if "digital native" in s else "smb")
    industry = "fsi" if "fsi" in s else "retail" if "retail" in s else "generic"
    return segment, industry


def classify_question(question):
    """Route a chat question: pricing/what-if → Code Interpreter; else FAQ."""
    if re.search(r"\b(cost\w*|price\w*|pricing|cheap\w*|expensive|what.?if|instead|swap|replace|budget)\b",
                 question.lower()):
        return "what_if_question"
    return "faq_query"


def _invoke_agent(payload):
    import uuid
    result = _agent.invoke_agent_runtime(
        agentRuntimeArn=RUNTIME_ARN,
        runtimeSessionId=f"mail-{uuid.uuid4().hex}",
        payload=json.dumps(payload).encode(),
        contentType="application/json", accept="application/json")
    return _extract_trailing_json(result["response"].read().decode("utf-8", "replace"))


def answer_question(question, ctx):
    field = classify_question(question)
    # Simple pricing arithmetic (remove/double/halve/N-to-M a service) is
    # answered deterministically from the saved cost lines — exact, instant,
    # no model involved. Only judgement questions reach the agent.
    if field == "what_if_question" and ctx.get("cost_lines"):
        answer = tier1.what_if_deterministic(question, ctx["cost_lines"])
        if answer:
            return "WHAT-IF PRICING (deterministic)\n" + answer
    parsed = _invoke_agent({
        "segment": ctx["segment"], "industry": ctx["industry"],
        "region": ctx.get("region", "us-east-1"), "sow_text": "",
        "diagram_text": "", "diagram_filename": "diagram.mmd",
        "services": ctx["services"], "edges": ctx["edges"],
        "extraction_confirmed": True, "user_id": "gmail-poller",
        field: question,
    })
    if not parsed:
        return "The agent did not return an answer — try rephrasing, or ask on the web page."
    lines = []
    what_if = parsed.get("what_if")
    if what_if and what_if.get("status") != "unavailable":
        # The what-if tool returns {code, stdout, stderr}: stdout carries the
        # computed answer. Never leak code or tracebacks into the email.
        stdout = (what_if.get("stdout") or "").strip()
        if stdout:
            try:
                stdout = json.loads(stdout)
            except (json.JSONDecodeError, TypeError):
                pass
            lines += ["WHAT-IF PRICING", str(stdout), ""]
        else:
            lines += ["WHAT-IF PRICING",
                      "Could not compute — ask with concrete specifics, e.g. "
                      "'what if RDS moves to db.t4g.medium with 50 GB'.", ""]
    faq = parsed.get("faq")
    if faq and faq.get("status") != "unavailable":
        results = [r for r in (faq.get("results") or []) if (r.get("text") or "").strip()]
        lines.append("FAQ MATCHES" if results else "No FAQ matches found.")
        for r in results[:3]:
            lines.append(f"- {r['text'].strip()[:400]}")
        lines.append("")
    if not lines:
        reason = (what_if or faq or {}).get("reason", "feature unavailable on this deployment")
        verdict = (parsed.get("verdict") or {})
        lines = [f"Chat feature unavailable ({reason}).",
                 f"Re-ran the review instead — verdict: {verdict.get('result', '?')} — "
                 f"{verdict.get('reasoning', '')}"]
    return "\n".join(lines).strip()


def client_from_filename(filename):
    """'AnyCompanyCorp_SOW_Partner.docx' → 'AnyCompanyCorp' — the client whose
    own name must NOT count as brand contamination."""
    stem = re.split(r"[._\s-]sow\b", (filename or "").rsplit(".", 1)[0], flags=re.I)[0]
    return stem.replace("_", " ").replace("-", " ").strip()


def review_report(sow_text, subject, filename=""):
    segment, industry = _options_from_subject(subject)
    result = tier1.run(
        {"sow_text": sow_text, "segment": segment, "industry": industry,
         "services": [], "edges": [],
         "client_name": client_from_filename(filename)},
        _banned_brands())
    # Reuse the email formatter — identical copy-paste-friendly layout.
    from email_review import format_report
    return result, format_report(result, filename or subject or "SOW")


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------


def summary_text(counts):
    return (f"Processed {counts['reviews']} SOW review(s), "
            f"{counts['chats']} chat repl(ies), "
            f"{counts['skipped']} skipped. Replies are in your inbox.")


def handler(event, context):  # noqa: ARG001 — Lambda signature
    # Invoked via the CloudFront-fronted Function URL: the owner's "ping".
    is_http = isinstance(event, dict) and "requestContext" in event
    counts = {"reviews": 0, "chats": 0, "skipped": 0}
    token = _access_token()
    query = f"from:{OWNER} -label:{LABEL} newer_than:7d {{to:{ALIAS} subject:SOW}}"
    listing = _http(f"{GMAIL}/messages?q={urllib.parse.quote(query)}&maxResults=10",
                    token=token)
    for ref in listing.get("messages", []):
        msg = _http(f"{GMAIL}/messages/{ref['id']}?format=full", token=token)
        payload = msg.get("payload", {})
        sender = _header(payload, "From").lower()
        if OWNER not in sender:            # hard allowlist, defence in depth
            _mark_processed(token, ref["id"])
            counts["skipped"] += 1
            continue
        thread = {
            "thread_id": msg["threadId"],
            "subject": _header(payload, "Subject") or "SOW review",
            "message_id_header": _header(payload, "Message-ID"),
        }
        # Claim the message BEFORE replying: our replies also match the query,
        # and labelling first makes reprocessing impossible even on a crash
        # between send and label.
        _mark_processed(token, ref["id"])

        filename, sow_text = _attachment_text(token, ref["id"], payload)
        if sow_text:
            _send_reply(token, thread,
                        f"Received {filename} — running the review now. "
                        "Results follow in a separate reply.")
            result, report = review_report(sow_text, thread["subject"], filename)
            ex = result.get("extraction", {})
            segment, industry = _options_from_subject(thread["subject"])
            _save_ctx(thread["thread_id"], {
                "segment": segment,
                "industry": industry,
                "services": ex.get("services", []),
                "edges": ex.get("edges", []),
                "cost_lines": (result.get("cost") or {}).get("lines", []),
            })
            _send_reply(token, thread, report)
            counts["reviews"] += 1
            continue

        ctx = _load_ctx(thread["thread_id"])
        question = strip_quoted(_plain_body(payload))
        if ctx and question:
            _send_reply(token, thread, answer_question(question, ctx))
            counts["chats"] += 1
        elif question:
            _send_reply(token, thread,
                        "No review context for this thread — send the SOW as a "
                        ".docx/.txt/.md attachment first.")
            counts["skipped"] += 1
        else:
            counts["skipped"] += 1

    if is_http:
        return {"statusCode": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": summary_text(counts)}
    return {"status": "done", **counts}

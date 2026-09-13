"""poc-validator-email-review — email-in / email-out SOW reviews.

Flow: SES inbound receipt rule stores the raw MIME message in the mail bucket
under inbox/ → S3 event invokes this handler → the first .docx/.txt/.md
attachment is extracted → Tier 1 deterministic review (rule packs, delivery
delivery checks, Well-Architected lenses, pricing, heuristic SOW score) → a
plain-text reply formatted for copy-paste goes back to the sender via SES.

Security posture:
  * Replies ONLY to senders on the ALLOWED_SENDERS allowlist — anyone else's
    mail is dropped silently (no bounce: no oracle for address discovery).
  * SES spam/virus verdict headers are honoured — failures are dropped.
  * v1 is deterministic-only: no model ever sees the email, so a hostile
    attachment has no prompt-injection surface at all.
"""

import email
import email.policy
import json
import os
import re
import urllib.parse
import zipfile
from io import BytesIO

import boto3

import tier1

_region = os.environ.get("AWS_REGION", "us-east-1")
_s3 = boto3.client("s3", region_name=_region)
_ses = boto3.client("sesv2", region_name=_region)

FROM_ADDRESS = os.environ["FROM_ADDRESS"]
CONFIG_BUCKET = os.environ["CONFIG_BUCKET"]
ALLOWED_SENDERS = {
    a.strip().lower() for a in os.environ.get("ALLOWED_SENDERS", "").split(",") if a.strip()
}
MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024

_banned_cache = {"value": None}


def _banned_brands():
    if _banned_cache["value"] is None:
        try:
            obj = _s3.get_object(Bucket=CONFIG_BUCKET, Key="config/banned-clients.json")
            _banned_cache["value"] = json.loads(obj["Body"].read()).get("banned", [])
        except Exception:  # noqa: BLE001 — missing config just disables the check
            _banned_cache["value"] = []
    return _banned_cache["value"]


def docx_to_text(data):
    with zipfile.ZipFile(BytesIO(data)) as zf:
        xml = zf.read("word/document.xml").decode("utf-8", "ignore")
    xml = re.sub(r"</w:p>", "\n", xml)
    xml = re.sub(r"<[^>]+>", "", xml)
    return re.sub(r"\n{3,}", "\n\n", xml).strip()


def extract_sow(msg):
    """Return (filename, text) for the first usable attachment, else (None, None)."""
    for part in msg.walk():
        filename = part.get_filename() or ""
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        if len(payload) > MAX_ATTACHMENT_BYTES:
            continue
        lower = filename.lower()
        if lower.endswith(".docx"):
            try:
                return filename, docx_to_text(payload)
            except Exception:  # noqa: BLE001 — malformed docx: try the next part
                continue
        if lower.endswith((".txt", ".md")):
            return filename, payload.decode("utf-8", "ignore")
    return None, None


def _verdicts_pass(msg):
    for header in ("X-SES-Spam-Verdict", "X-SES-Virus-Verdict"):
        value = (msg.get(header) or "").strip().upper()
        if value and value != "PASS":
            return False
    return True


def _sender_address(msg):
    raw = msg.get("Reply-To") or msg.get("From") or ""
    match = re.search(r"<([^>]+)>", raw)
    return (match.group(1) if match else raw).strip().lower()


def format_report(result, filename):
    """Plain text, phone-copy-paste friendly. No markup, 78-col-ish lines."""
    lines = []
    verdict = result.get("verdict") or {}
    lines.append(f"SOW REVIEW — {filename}")
    lines.append(f"Verdict: {verdict.get('result', '?')} — {verdict.get('reasoning', '')}")
    counts = result.get("counts") or {}
    chips = " · ".join(f"{k}: {v}" for k, v in counts.items() if v)
    lines.append(f"Findings: {chips or 'none'}")
    lines.append("Tier: deterministic (rule packs, no model) — grounded checks only")
    lines.append("")

    findings = result.get("findings") or []
    if findings:
        lines.append("FINDINGS")
        for f in findings:
            lines.append(f"[{f['severity']}] {f['rule_id']} — {f['title']}")
            if f.get("remediation"):
                lines.append(f"    Fix: {f['remediation']}")
        lines.append("")

    klv = [f for f in findings if f["rule_id"].startswith("KLV")]
    lines.append("DELIVERY CHECKS")
    lines.append("  Issues listed above." if klv else
                 "  All pass: no brand contamination, cost >= $2,000/mo, timeline >= 6 weeks.")
    lines.append("")

    applied = result.get("evidence_applied") or []
    if applied:
        lines.append("CREDITED FROM THE DOCUMENT (text evidence applied to the checks)")
        for a in applied:
            lines.append(f"  - {a['attribute']}: \"{a['evidence'][:90]}\"")
        lines.append("")

    lenses = result.get("lenses") or []
    if lenses:
        lines.append("WELL-ARCHITECTED LENSES APPLIED")
        for lens in lenses:
            lines.append(f"  - {lens['name']}: {lens['url']}")
        lines.append("")

    sow = result.get("sow")
    if sow:
        lines.append(f"SOW SCORE (heuristic floor): {sow['score']}/100 — {sow['rating']}")
        for c in sow.get("criteria", []):
            if c.get("fix"):
                lines.append(f"  Gap {c['id']} {c['name']}: {c['fix']}")
        lines.append("")

    cost = result.get("cost") or {}
    if cost:
        lines.append(f"RULE-PACK COST MODEL: ${cost.get('total', 0):,.2f}/mo "
                     f"(baseline ${cost.get('baseline', 0):,.2f}, region {cost.get('region', '')})")
        lines.append("")

    ex = result.get("extraction") or {}
    if ex.get("services"):
        lines.append(f"SERVICES (grounded in the document): {', '.join(ex['services'])}")
        lines.append("")

    lines.append("For the model-assisted review, open the gatekeeper page and run")
    lines.append("'Run full agent review' on the same document.")
    return "\n".join(lines)


def handler(event, context):  # noqa: ARG001 — Lambda signature
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        raw = _s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        msg = email.message_from_bytes(raw, policy=email.policy.default)

        sender = _sender_address(msg)
        if sender not in ALLOWED_SENDERS:
            print(f"drop: sender {sender!r} not on allowlist")
            continue
        if not _verdicts_pass(msg):
            print("drop: SES spam/virus verdict failed")
            continue

        filename, sow_text = extract_sow(msg)
        subject = msg.get("Subject") or "SOW review"
        if not sow_text:
            body = ("No usable SOW found. Attach the document as .docx, .txt or .md "
                    "and send again.")
        else:
            result = tier1.run(
                {"sow_text": sow_text, "segment": "smb", "industry": "generic",
                 "services": [], "edges": []},
                _banned_brands(),
            )
            body = format_report(result, filename)

        _ses.send_email(
            FromEmailAddress=FROM_ADDRESS,
            Destination={"ToAddresses": [sender]},
            Content={"Simple": {
                "Subject": {"Data": f"Re: {subject}"},
                "Body": {"Text": {"Data": body}},
            }},
        )
        print(f"replied to {sender} for s3://{bucket}/{key}")
    return {"status": "done"}

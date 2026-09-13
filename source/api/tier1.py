"""Tier 1 — deterministic SOW review that never touches a model.

Runs the same rule packs, integration chaining, pricing and heuristic SOW
scoring as the AgentCore path, but entirely inside this Lambda (~$0.0003 and
<1s per run instead of ~$0.05 and ~40s). Everything here is grounded by
construction: services are only reported with the exact text evidence that
matched them, delivery checks are pure regex/word-list, and the
Well-Architected lens selection is a static mapping to official AWS lens
documents.

The ``pocvalidator.core`` package and its ``config/data/`` YAML catalogue are bundled
into the Lambda asset by the CDK local bundler; ``POCVALIDATOR_ROOT`` points
the catalogue loader at ``/var/task``.
"""

import dataclasses
import re

from pocvalidator.core import catalog, engine, sow
from pocvalidator.core.models import Severity

TIER_LABEL = "deterministic"

# ---------------------------------------------------------------------------
# Grounded service detection — catalogue names searched verbatim in the text.
# ---------------------------------------------------------------------------


def _name_variants(service_id, definition):
    name = definition["name"].lower()
    short = name.replace("amazon ", "").replace("aws ", "")
    variants = {name, short, service_id.replace("_", " ")}
    return {v for v in variants if len(v) >= 3}


# Phrases that mark a region of the document as describing what will NOT be
# built. A service named only inside such a region is out of scope, and must
# not be treated as in-scope, priced, or judged by the rule packs.
#
# Found on a real SOW: "operation of custom or open-weight models on Amazon
# SageMaker or Amazon EC2" sat under "Out of Scope". EC2 was detected as
# in-scope, priced at $179 of a $428 estimate, and raised a HIGH finding that
# EC2 was not in a private subnet — for a service the architecture does not
# contain.
_EXCLUSION_MARKERS = (
    "out of scope", "out-of-scope", "not in scope", "not in-scope",
    "excluded", "exclusions", "will not", "shall not", "does not include",
    "excluding", "no changes to", "outside the scope",
)
# How far an exclusion heading governs. A heading applies to its section, not
# to the whole document, so this is deliberately bounded rather than "until
# the next heading" — headings are not reliably detectable in extracted text.
_EXCLUSION_SPAN = 1200


def _exclusion_regions(text_lower):
    """Character ranges that describe work explicitly NOT being done."""
    regions = []
    for marker in _EXCLUSION_MARKERS:
        start = 0
        while True:
            idx = text_lower.find(marker, start)
            if idx < 0:
                break
            regions.append((idx, idx + _EXCLUSION_SPAN))
            start = idx + len(marker)
    return regions


def _in_exclusion(idx, regions):
    return any(lo <= idx < hi for lo, hi in regions)


def detect_services(sow_text):
    """Return (service_ids, grounding) where grounding maps each detected
    service to the exact evidence snippet that matched it. A service with no
    match in the text is simply not reported — nothing is ever inferred."""
    text_lower = sow_text.lower()
    regions = _exclusion_regions(text_lower)
    services, grounding = [], {}
    for service_id, definition in catalog.service_defs().items():
        for variant in sorted(_name_variants(service_id, definition), key=len, reverse=True):
            # Take the first mention that is NOT inside an exclusion region, so
            # a service named once under "Out of Scope" is not treated as
            # in-scope. A service mentioned in both places stays in scope.
            idx, scan = -1, 0
            while True:
                hit = text_lower.find(variant, scan)
                if hit < 0:
                    break
                if not _in_exclusion(hit, regions):
                    idx = hit
                    break
                scan = hit + len(variant)
            if idx < 0:
                continue
            start = max(0, idx - 40)
            end = min(len(sow_text), idx + len(variant) + 40)
            services.append(service_id)
            grounding[service_id] = {
                "grounded": True,
                "matched": variant,
                "evidence": sow_text[start:end].replace("\n", " ").strip(),
            }
            break
    return services, grounding


def detect_services_in_cost_table(sow_text):
    """Service ids named in the document's own COST TABLE rows.

    A SOW's pricing table is the most explicit statement of what is being
    bought, but prose detection alone misses it: a row reads
    "Amazon VPC - AWS PrivateLink | 1 VPC Interface Endpoint | $19.98", and the
    service name may appear nowhere else in the narrative. Detecting from the
    cost table as well as the prose means the validator judges what the customer
    is actually being charged for.
    """
    rows = [ln for ln in sow_text.split("\n")
            if re.search(r"\$\s*[\d,]+(?:\.\d{2})?\s*$", ln)]
    if not rows:
        return [], {}
    table_text = "\n".join(rows)
    ids, grounding = detect_services(table_text)
    for sid in ids:
        grounding[sid]["source"] = "cost_table"
    return ids, grounding


def ground_extraction(extraction, sow_text):
    """Annotate a model-produced extraction with per-service text evidence.

    Used on the agent path's awaiting_confirmation payload so the browser can
    show which extracted services actually appear in the document and which
    are the model's inference (candidates for unticking)."""
    _, grounding = detect_services(sow_text)
    annotated = {}
    for service_id in extraction.get("services", []):
        annotated[service_id] = grounding.get(
            service_id,
            {"grounded": False, "matched": "", "evidence": ""},
        )
    extraction["grounding"] = annotated
    ungrounded = [s for s, g in annotated.items() if not g["grounded"]]
    if ungrounded:
        note = f"No text evidence found for: {', '.join(sorted(ungrounded))} — verify before confirming."
        extraction["notes"] = (extraction.get("notes") or "").strip()
        extraction["notes"] = (extraction["notes"] + " " + note).strip()
    return extraction


# ---------------------------------------------------------------------------
# Evidence-based attribute overrides — SOW text reaching the rule packs.
# ---------------------------------------------------------------------------
# The rule packs check node attributes; a confirmed service list alone carries
# only catalogue defaults, so "automated backups enabled" written in the SOW
# never used to reach SMB-002. These regexes turn explicit text evidence into
# config overrides. Grounded by construction: an attribute is only ever set
# to True when its evidence appears verbatim in the document — absence of
# evidence never changes a default, so nothing is ever assumed passing.

ATTRIBUTE_EVIDENCE = {
    "backup_enabled": r"automated backups?\s+(?:enabled|with|configured)|point[\s-]?in[\s-]?time recovery|backup retention",
    "multi_az": r"multi[\s-]?az|multiple availability zones|(?:2|two) (?:availability zones|azs)",
    "logging_enabled": r"access log(?:ging|s)|audit log|vpc flow logs|cloudtrail|shard[\s-]level|logging enabled",
    "encryption_at_rest": r"encrypt(?:ion|ed) at rest|kms encryption|server[\s-]side encryption",
    "encryption_in_transit": r"encryption in transit|\btls\b|\bssl\b|https[\s-]only",
    "private_subnet": r"private subnets?",
    "waf_enabled": r"\bwaf\b|web application firewall",
    "mfa_enabled": r"\bmfa\b|multi[\s-]?factor",
    "dlq_configured": r"dead[\s-]?letter queues?|\bdlqs?\b",
    "rotation_enabled": r"(?:automatic|secrets?) rotation|rotation enabled",
    "versioning": r"\bversioning\b",
    "throttling_enabled": r"\bthrottl",
    "guardrails_enabled": r"\bguardrails?\b",
}


def attribute_overrides(sow_text, services):
    """Return (overrides, applied): per-service config overrides justified by
    text evidence, plus the evidence trail for the report."""
    text_lower = sow_text.lower()
    overrides, applied = {}, []
    for attribute, pattern in ATTRIBUTE_EVIDENCE.items():
        match = re.search(pattern, text_lower)
        if not match:
            continue
        start = max(0, match.start() - 40)
        snippet = sow_text[start:match.end() + 40].replace("\n", " ").strip()
        touched = []
        for service_id in services:
            if attribute in catalog.service_defs().get(service_id, {}).get("attributes", []):
                overrides.setdefault(service_id, {})[attribute] = True
                touched.append(service_id)
        if touched:
            applied.append({"attribute": attribute, "evidence": snippet,
                            "services": touched})
    return overrides, applied


# ---------------------------------------------------------------------------
# Deterministic what-if pricing — no model, exact arithmetic on cost lines.
# ---------------------------------------------------------------------------


def what_if_deterministic(question, lines):
    """Answer simple pricing questions from the cost lines alone. Handles
    remove/double/halve/N-times for a named service; returns None when the
    question needs judgement (caller falls back to the agent)."""
    q = question.lower()
    total = sum(float(l.get("monthly_cost") or 0) for l in lines)

    def service_lines(name_fragment):
        return [l for l in lines
                if name_fragment in (l.get("node_name") or "").lower()
                or name_fragment in (l.get("node_id") or "").lower()]

    target, matched = None, ""
    for l in lines:
        for candidate in ((l.get("node_id") or ""), (l.get("node_name") or "").lower()):
            frag = candidate.lower().replace("amazon ", "").replace("aws ", "")
            if frag and frag in q and len(frag) > len(matched):
                target, matched = frag, frag
    if not target:
        return None
    affected = service_lines(target)
    affected_total = sum(float(l.get("monthly_cost") or 0) for l in affected)

    scale = None
    if re.search(r"\b(remove[sd]?|drop(?:ped|s)?|delete[sd]?|without)\b", q):
        scale = 0.0
    elif re.search(r"\b(double[sd]?|twice|2x)\b", q):
        scale = 2.0
    elif re.search(r"\b(halv\w*|half|50%)\b", q):
        scale = 0.5
    else:
        m = re.search(r"from\s+(\d+(?:\.\d+)?)\s+to\s+(\d+(?:\.\d+)?)", q)
        if m and float(m.group(1)) > 0:
            scale = float(m.group(2)) / float(m.group(1))
    if scale is None:
        return None

    new_total = total - affected_total + affected_total * scale
    verb = ("Removing" if scale == 0 else
            f"Scaling ({scale:g}x)")
    return (f"{verb} {matched}: that service is ${affected_total:,.2f}/mo of the "
            f"${total:,.2f}/mo total. New total: ${new_total:,.2f}/mo "
            f"({new_total - total:+,.2f}). Deterministic arithmetic on the "
            f"rule-pack cost model — re-price on calculator.aws before quoting.")


# ---------------------------------------------------------------------------
# Delivery-standard checks — contamination, cost floor, timeline.
# ---------------------------------------------------------------------------

MIN_MONTHLY_COST = 2000.0
MIN_TIMELINE_WEEKS = 6


def _finding(rule_id, severity, title, rationale, remediation, pillar="Operational Excellence"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "pillar": pillar,
        "source": "Delivery-standard checks",
        "rationale": rationale,
        "remediation": remediation,
        "doc_url": "",
    }


def delivery_checks(sow_text, banned_brands, client_name=""):
    """Deterministic delivery-standard checks on the raw SOW text."""
    findings = []
    text_lower = sow_text.lower()
    client_lower = (client_name or "").strip().lower()

    hits = []
    for brand in banned_brands:
        b = brand.strip().lower()
        if not b or (client_lower and (b in client_lower or client_lower in b)):
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(b) + r"(?![a-z0-9])", text_lower):
            hits.append(brand)
    if hits:
        findings.append(_finding(
            "DLV-BRAND", "Critical",
            f"Brand contamination: {', '.join(sorted(hits))}",
            "Another client's name appears in this document. Only the current client may be named.",
            "Remove every occurrence (body, tables, headers, footers, captions) before delivery.",
            pillar="Security",
        ))

    monthly = [float(m.replace(",", "")) for m in re.findall(
        r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:/|per\s+)mo", text_lower)]
    monthly += [float(m.replace(",", "")) for m in re.findall(
        r"monthly[^$\n]{0,40}\$\s*([\d,]+(?:\.\d+)?)", text_lower)]
    # Cost tables often state only "Annual: $X" next to the monthly total —
    # annual/12 recovers the monthly figure independent of table layout.
    monthly += [round(float(m.replace(",", "")) / 12, 2) for m in re.findall(
        r"annual:?\s*\$\s*([\d,]+(?:\.\d+)?)", text_lower)]
    if monthly and max(monthly) < MIN_MONTHLY_COST:
        findings.append(_finding(
            "DLV-COST", "High",
            f"Monthly cost ${max(monthly):,.2f} is below the ${MIN_MONTHLY_COST:,.0f} minimum engagement",
            "The configured minimum engagement is $2,000/month.",
            "Re-scope or re-price the engagement to meet the minimum.",
            pillar="Cost Optimization",
        ))
    elif not monthly:
        findings.append(_finding(
            "DLV-COST", "Medium",
            "No monthly cost figure found in the SOW text",
            "Every SOW must state its monthly cost; pricing must match the estimate exactly.",
            "Add the cost table with a stated $/month total.",
            pillar="Cost Optimization",
        ))

    weeks = [int(w) for w in re.findall(r"week\s*(\d{1,2})", text_lower)]
    weeks += [int(w) for w in re.findall(r"(\d{1,2})[\s-]*weeks?", text_lower)]
    if weeks and max(weeks) < MIN_TIMELINE_WEEKS:
        findings.append(_finding(
            "DLV-TIME", "High",
            f"Timeline appears to be {max(weeks)} weeks — minimum is {MIN_TIMELINE_WEEKS}",
            "Engagements shorter than 6 weeks under-scope delivery and knowledge transfer.",
            "Extend the timeline to at least 6 weeks (8 for HIPAA + ML).",
        ))
    elif not weeks:
        findings.append(_finding(
            "DLV-TIME", "Low",
            "No week-based timeline found in the SOW text",
            "The SOW should break delivery into dated weekly phases.",
            "Add a phased timeline table with week numbers.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Official Well-Architected lens selection — static, official docs only.
# ---------------------------------------------------------------------------

_FRAMEWORK = {
    "name": "AWS Well-Architected Framework",
    "url": "https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html",
    "why": "Baseline for every review.",
}
_LENSES = {
    "serverless": {
        "name": "Serverless Applications Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/welcome.html",
    },
    "genai": {
        "name": "Generative AI Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/welcome.html",
    },
    "ml": {
        "name": "Machine Learning Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/machine-learning-lens/welcome.html",
    },
    "analytics": {
        "name": "Data Analytics Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/analytics-lens/welcome.html",
    },
    "iot": {
        "name": "IoT Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/iot-lens/welcome.html",
    },
    "fsi": {
        "name": "Financial Services Industry Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/welcome.html",
    },
    "saas": {
        "name": "SaaS Lens",
        "url": "https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/welcome.html",
    },
}


def select_lenses(industry, services, sow_text=""):
    """Map the customer's industry and detected service mix onto the official
    AWS Well-Architected lenses that apply. Static mapping — never invented."""
    text_lower = (sow_text or "").lower()
    svc = set(services)
    picked = [dict(_FRAMEWORK)]

    def add(key, why):
        lens = dict(_LENSES[key])
        lens["why"] = why
        picked.append(lens)

    if svc & {"lambda", "apigateway"}:
        add("serverless", "Lambda / API Gateway are core to this design.")
    if "bedrock" in svc:
        add("genai", "Amazon Bedrock generative AI workload.")
    if "sagemaker" in svc or "sagemaker" in text_lower:
        add("ml", "Custom model training (SageMaker) in scope.")
    if svc & {"kinesis", "redshift"}:
        add("analytics", "Streaming / analytics services in the design.")
    if any(t in text_lower for t in ("iot core", "greengrass", "mqtt", "edge device")):
        add("iot", "IoT edge devices and telemetry in the SOW.")
    if industry == "fsi":
        add("fsi", "Customer operates in financial services.")
    if industry == "retail" and "saas" in text_lower:
        add("saas", "Multi-tenant SaaS delivery model described.")
    return picked


# ---------------------------------------------------------------------------
# Full deterministic run — same response shape as the agent path.
# ---------------------------------------------------------------------------


def run(payload, banned_brands):
    sow_text = payload.get("sow_text") or ""
    segment = payload["segment"]
    industry = payload["industry"]
    region = payload.get("region") or "us-east-1"
    services = payload.get("services") or []
    edges = [tuple(e) for e in (payload.get("edges") or [])]

    if services:
        _, grounding = detect_services(sow_text)
        grounding = {s: grounding.get(s, {"grounded": False, "matched": "", "evidence": ""})
                     for s in services}
    else:
        services, grounding = detect_services(sow_text)
        edges = []

    sow_score = sow.score_heuristic(sow_text) if sow_text else None
    overrides, evidence_applied = attribute_overrides(sow_text, services)
    graph = engine.graph_from_selection(
        segment_id=segment, industry_id=industry, region=region,
        description="tier1 deterministic review",
        service_ids=services, edges=edges,
        overrides=overrides,
    )
    report = engine.validate(graph, sow_score)
    verdict, reasoning = report.verdict

    local = delivery_checks(sow_text, banned_brands, payload.get("client_name", ""))
    counts = {severity.value: report.count(severity) for severity in Severity}
    for f in local:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    result = {
        "status": "complete",
        "tier": TIER_LABEL,
        "model_assisted": False,
        "verdict": {"result": verdict, "reasoning": reasoning},
        "counts": counts,
        "findings": local + [
            {
                "rule_id": f.rule_id, "severity": f.severity.value, "title": f.title,
                "pillar": f.pillar, "source": f.source_label, "rationale": f.rationale,
                "remediation": f.remediation, "doc_url": f.doc_url,
            }
            for f in report.sorted_findings
        ],
        "conflicts": [
            {
                "attribute": c.attribute, "node": c.node_name,
                "segment_position": c.segment_position,
                "industry_position": c.industry_position, "resolution": c.resolution,
            }
            for c in report.conflicts
        ],
        "integrations": [
            {"from": e.source, "to": e.target, "type": e.edge_type.value,
             "pattern": e.pattern, "note": e.note}
            for e in report.graph.edges
        ],
        "cost": {
            "baseline": report.cost.baseline,
            "compliance_premium": report.cost.premium,
            "total": report.cost.total,
            "currency": report.cost.currency,
            "region": report.cost.region,
            "as_of": report.cost.as_of,
            "lines": [dataclasses.asdict(line) for line in report.cost.lines],
        },
        "recommendations": [
            {"title": r.title, "kind": r.kind_label, "url": r.url,
             "summary": r.summary, "why": why}
            for r, why in report.recommendations
        ],
        "evidence": report.evidence,
        "extraction": {"services": services, "edges": [list(e) for e in edges],
                       "grounding": grounding},
        "evidence_applied": evidence_applied,
        "lenses": select_lenses(industry, services, sow_text),
        "gateway_available": False,
    }
    if sow_score is not None:
        result["sow"] = {
            "score": sow_score.total,
            "rating": sow_score.rating,
            "model_assisted": sow_score.model_assisted,
            "summary": sow_score.summary,
            "criteria": [
                {
                    "id": c.criterion_id, "name": c.name, "weight": c.weight,
                    "band": c.band, "band_label": c.band_label,
                    "justification": c.justification,
                    "fix": c.gap_fix if c.is_gap else "",
                }
                for c in sow_score.scores
            ],
        }
    return result

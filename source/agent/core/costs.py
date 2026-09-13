"""Cost reconciliation: does the SOW's own stated price resemble our estimate?

The gap this closes: the pricing phase (see ``pricing.py``) prices the
*architecture* — the services and usage the validator was told about — in
total isolation from whatever dollar figure the SOW document itself claims.
Nothing previously compared the two. On a real customer SOW that meant a
document stating **$10,501.18/month** sailed through review next to a
computed estimate of **$427.64/month** — a 24.6x gap — with no finding at
all, because every existing check only verifies the SOW's *internal*
arithmetic (do the rows sum to the stated total), never asks whether that
total is independently plausible.

Two rules come out of this module:

  COST-01  Does a stated total exist, and if so does it reconcile with the
           computed estimate within tolerance? (missing / ambiguous / High
           divergence / passes)
  COST-02  Is the reconciliation even complete — does the SOW name services
           or foundation models this pricing catalogue has no rate for at
           all? (Medium, only meaningful once COST-01 has a stated figure)

Same two principles as ``pricing.py``, applied to a different kind of
number:

1. All arithmetic here is Python, never a model.
2. Nothing is ever estimated, rounded, or "helpfully" adjusted. The stated
   figure is exactly what regex extraction recovered from the document; the
   estimated figure is exactly what ``pricing.estimate()`` computed. If
   extraction is ambiguous (more than one plausible candidate in the same
   tier), that ambiguity is reported, not resolved by picking one.

The three extraction patterns below ($X/mo, "monthly ... $X", "annual: $X"
÷12) are the same patterns ``source/api/tier1.py``'s ``delivery_checks``
already proved out for its own "is there a cost floor" check — reused here
verbatim rather than re-invented, plus a "total ... monthly ... $X" tier
that gives the labelled grand total priority over incidental per-service
"$X/mo" mentions elsewhere in the document. A table cell written as
``Total Estimated Monthly Cost | $10,501.18`` is not a special case: the
"total" and "monthly" tokens and the dollar figure are still there, just
separated by a pipe instead of a sentence, which the same regex tolerates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import catalog
from .models import Finding, Severity

DEFAULT_TOLERANCE = 0.25  # 25% — see config.COST_RECONCILIATION_TOLERANCE

RULE_RECONCILIATION = "COST-01"
RULE_COVERAGE = "COST-02"

_PILLAR = "Cost Optimization"
_SOURCE = "cost-reconciliation"
_SOURCE_LABEL = "Cost reconciliation"

# ---------------------------------------------------------------------------
# Stated-total extraction.
# ---------------------------------------------------------------------------

# Tier A: an explicit labelled grand total — "total ... monthly ... $X" (or
# the words in the reverse order some templates use). This is what a table
# row like "Total Estimated Monthly Cost | $10,501.18" matches: the pipe is
# just more "anything but $ or newline" to the regex.
_TOTAL_MONTHLY = re.compile(
    r"total[^$\n]{0,60}monthly[^$\n]{0,40}\$\s*([\d,]+(?:\.\d+)?)"
    r"|monthly[^$\n]{0,60}total[^$\n]{0,40}\$\s*([\d,]+(?:\.\d+)?)",
    re.IGNORECASE,
)

# Tier B: the same two patterns tier1.delivery_checks uses for its cost-floor
# check — "$X/mo" and "monthly ... $X" without a labelled "total".
_PER_MONTH = re.compile(r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:/|per\s+)mo\b", re.IGNORECASE)
_MONTHLY_PREFIXED = re.compile(
    r"monthly[^$\n]{0,40}\$\s*([\d,]+(?:\.\d+)?)", re.IGNORECASE
)

# Tier C: tier1's annual/12 recovery, for documents that only ever state a
# yearly figure next to the monthly one.
_ANNUAL = re.compile(r"annual:?\s*\$\s*([\d,]+(?:\.\d+)?)", re.IGNORECASE)


def _to_float(raw: str) -> float:
    return float(raw.replace(",", ""))


@dataclass
class StatedCost:
    """What the document itself claims its monthly cost is, or isn't."""

    amount: float | None
    candidates: list[float] = field(default_factory=list)
    ambiguous: bool = False


def extract_stated_monthly_total(sow_text: str) -> StatedCost:
    """Recover the SOW's own stated monthly total, or say why it couldn't.

    Tries tiers in order of specificity (labelled total, then bare $/mo or
    "monthly ... $", then annual ÷ 12) and stops at the first tier that
    produced any match. Within that tier, if every match agrees (same
    figure quoted more than once) that figure is returned; if they
    disagree, the result is marked ambiguous with every distinct candidate
    listed — never silently resolved by picking one.
    """
    tiers: list[list[float]] = [
        [
            _to_float(group)
            for match in _TOTAL_MONTHLY.finditer(sow_text)
            for group in match.groups()
            if group
        ],
        [_to_float(v) for v in _PER_MONTH.findall(sow_text)]
        + [_to_float(v) for v in _MONTHLY_PREFIXED.findall(sow_text)],
        [round(_to_float(v) / 12, 2) for v in _ANNUAL.findall(sow_text)],
    ]

    for tier in tiers:
        if not tier:
            continue
        distinct = sorted({round(v, 2) for v in tier})
        if len(distinct) == 1:
            return StatedCost(amount=distinct[0], candidates=distinct, ambiguous=False)
        return StatedCost(amount=None, candidates=distinct, ambiguous=True)

    return StatedCost(amount=None, candidates=[], ambiguous=False)


# ---------------------------------------------------------------------------
# Coverage gaps — named services/models this catalogue has no rate for.
# ---------------------------------------------------------------------------

# Grounded, not inferred: every entry below is either an exact regex match on
# the document's own text (foundation model names, captured verbatim so the
# finding quotes exactly what the SOW said) or a well-known AWS service name
# that this sample's ~20-service catalogue (config/data/pricing.yaml) does not
# price. `catalog.pricing()["rates"]` covers every service the catalogue
# knows about (see test_pocvalidator.test_pricing_rates_are_subset_of_services
# -equivalent invariant), so the gap is never "in the catalogue but unpriced"
# — it is always "the catalogue has no concept of this at all", which is
# exactly the Bedrock case that motivated this module: Amazon Bedrock has a
# flat per-token rate with no notion of *which* foundation model is running,
# so "Claude Opus 4.5" on Bedrock is invisible to the estimate even though
# Bedrock itself is priced.
_BEDROCK_MODEL = re.compile(
    r"claude\s+(?:opus|sonnet|haiku)(?:\s+\d+(?:\.\d+)?(?:\s*/\s*\d+(?:\.\d+)?)?)?",
    re.IGNORECASE,
)
_OTHER_FOUNDATION_MODELS = [
    re.compile(r"\bamazon\s+titan\b", re.IGNORECASE),
    re.compile(r"\bllama\s*\d", re.IGNORECASE),
    re.compile(r"\bmistral\b", re.IGNORECASE),
    re.compile(r"\bcohere\s+command\b", re.IGNORECASE),
]
_UNCATALOGUED_SERVICES = [
    ("Amazon SageMaker", re.compile(r"\bsagemaker\b", re.IGNORECASE)),
    ("Amazon Redshift", re.compile(r"\bredshift\b", re.IGNORECASE)),
    ("AWS Glue", re.compile(r"\bglue\b", re.IGNORECASE)),
    ("Amazon Textract", re.compile(r"\btextract\b", re.IGNORECASE)),
    ("Amazon Comprehend", re.compile(r"\bcomprehend\b", re.IGNORECASE)),
    ("Amazon Rekognition", re.compile(r"\brekognition\b", re.IGNORECASE)),
    ("AWS Direct Connect", re.compile(r"direct\s+connect", re.IGNORECASE)),
    ("AWS Transit Gateway", re.compile(r"transit\s+gateway", re.IGNORECASE)),
]


def find_unpriceable_services(sow_text: str) -> list[str]:
    """Named services/models in the SOW text this catalogue cannot price.

    Returns the matched text for foundation models (verbatim, so "Claude
    Opus 4.5" is reported exactly as written) and a fixed label for other
    uncatalogued AWS services, sorted and de-duplicated. A service is
    skipped if the catalogue can now resolve it (``catalog.resolve_service``)
    — this list is a practical snapshot, not a permanent claim, and should
    not keep flagging something the catalogue has since learned to price.
    """
    found: dict[str, str] = {}

    for match in _BEDROCK_MODEL.finditer(sow_text):
        label = re.sub(r"\s+", " ", match.group(0)).strip()
        found[label.lower()] = label

    for pattern in _OTHER_FOUNDATION_MODELS:
        match = pattern.search(sow_text)
        if match:
            label = re.sub(r"\s+", " ", match.group(0)).strip()
            found[label.lower()] = label

    for label, pattern in _UNCATALOGUED_SERVICES:
        if not pattern.search(sow_text):
            continue
        if catalog.resolve_service(label):
            continue
        found[label.lower()] = label

    return sorted(found.values())


# ---------------------------------------------------------------------------
# Reconciliation.
# ---------------------------------------------------------------------------


@dataclass
class ReconciliationResult:
    stated: StatedCost
    estimated: float
    tolerance: float
    ratio: float | None = None
    within_tolerance: bool | None = None
    unpriceable_services: list[str] = field(default_factory=list)


def reconcile(
    sow_text: str, estimated_total: float, tolerance: float = DEFAULT_TOLERANCE
) -> ReconciliationResult:
    """Compare the SOW's own stated total against the independent estimate.

    Never adjusts either number. ``tolerance`` is a fraction (0.25 = 25%):
    the two figures are considered reconciled if the larger is no more than
    ``tolerance`` bigger than the smaller.
    """
    stated = extract_stated_monthly_total(sow_text)
    unpriceable = find_unpriceable_services(sow_text)

    ratio = None
    within_tolerance = None
    if stated.amount is not None:
        lo, hi = sorted((stated.amount, estimated_total))
        if lo <= 0:
            ratio = 1.0 if hi <= 0 else float("inf")
        else:
            ratio = hi / lo
        within_tolerance = (ratio - 1) <= tolerance

    return ReconciliationResult(
        stated=stated,
        estimated=estimated_total,
        tolerance=tolerance,
        ratio=ratio,
        within_tolerance=within_tolerance,
        unpriceable_services=unpriceable,
    )


def build_findings(result: ReconciliationResult) -> tuple[list[Finding], list[dict]]:
    """Turn a ``ReconciliationResult`` into (findings, passed-checks).

    Exactly one of "no stated figure", "ambiguous", "diverges" or "passes"
    fires for COST-01. COST-02 is independent of that outcome: it fires
    whenever a stated figure exists at all and the SOW names something the
    catalogue cannot price, because that is what makes any comparison
    incomplete regardless of whether the two totals happen to be close.
    """
    findings: list[Finding] = []
    passed: list[dict] = []
    stated = result.stated

    def _finding(rule_id, title, severity, rationale, remediation):
        return Finding(
            rule_id=rule_id,
            node_id="sow",
            node_name="SOW cost statement",
            title=title,
            severity=severity,
            pillar=_PILLAR,
            source=_SOURCE,
            source_label=_SOURCE_LABEL,
            rationale=rationale,
            remediation=remediation,
            doc_url="",
        )

    if stated.ambiguous:
        figures = ", ".join(f"${c:,.2f}" for c in stated.candidates)
        findings.append(
            _finding(
                RULE_RECONCILIATION,
                "SOW states more than one monthly-cost figure — reconciliation is ambiguous",
                Severity.MEDIUM,
                f"Found {len(stated.candidates)} different candidate monthly totals "
                f"in the document ({figures}); the independent estimate is "
                f"${result.estimated:,.2f}/month. Which figure is the document's "
                "actual stated total could not be determined without guessing, so "
                "no comparison was made.",
                "State a single, unambiguous monthly cost total in the SOW (e.g. "
                "one clearly labelled 'Total Estimated Monthly Cost' row).",
            )
        )
    elif stated.amount is None:
        findings.append(
            _finding(
                RULE_RECONCILIATION,
                "SOW states no monthly cost to reconcile against the estimate",
                Severity.MEDIUM,
                f"The independently computed estimate is ${result.estimated:,.2f}/month, "
                "but the document itself states no monthly cost figure at all.",
                "Add a stated monthly cost total to the SOW (a cost table with a "
                "'Total Estimated Monthly Cost' row).",
            )
        )
    elif result.within_tolerance:
        passed.append(
            {
                "rule_id": RULE_RECONCILIATION,
                "title": "SOW's stated cost reconciles with the independent estimate",
                "detail": (
                    f"${stated.amount:,.2f} stated vs ${result.estimated:,.2f} "
                    f"estimated — within the {result.tolerance:.0%} tolerance."
                ),
            }
        )
    else:
        ratio_text = (
            "the estimate is $0.00 — no ratio is meaningful"
            if result.ratio is None or result.ratio == float("inf")
            else f"{result.ratio:.1f}x"
        )
        findings.append(
            _finding(
                RULE_RECONCILIATION,
                "SOW's stated cost diverges sharply from the independent estimate",
                Severity.HIGH,
                f"${stated.amount:,.2f} stated vs ${result.estimated:,.2f} estimated "
                f"({ratio_text}) — outside the {result.tolerance:.0%} "
                "reconciliation tolerance. Neither figure has been changed; both "
                "are reported exactly as stated/computed.",
                "Reconcile the two figures before this SOW is shared: identify what "
                "the stated total prices that the estimate does not (or vice-versa), "
                "and correct whichever one is wrong.",
            )
        )

    if stated.amount is not None and result.unpriceable_services:
        named = ", ".join(result.unpriceable_services)
        findings.append(
            _finding(
                RULE_COVERAGE,
                "Cost reconciliation is incomplete — some named items aren't priced by the catalogue",
                Severity.MEDIUM,
                f"The SOW names {named}, which this pricing catalogue has no rate "
                f"for. The computed estimate (${result.estimated:,.2f}/month) is "
                "therefore not a like-for-like comparison against the stated total "
                f"(${stated.amount:,.2f}/month) — part of the gap between them may "
                "be legitimate and explained by this coverage gap, not an error.",
                "Price the named items separately (e.g. via calculator.aws) and, if "
                "this should reconcile automatically in future, extend the pricing "
                "catalogue to model them.",
            )
        )

    return findings, passed

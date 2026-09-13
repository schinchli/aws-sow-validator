"""Scope of Work scoring.

Two-stage by design, following ADR 0014 in the reference sample ("deterministic
phase, no LLM"):

1. A deterministic heuristic pre-pass scans for the signals each criterion needs.
   It runs with no model, no network and no AWS account, and produces a floor
   score. This is what makes the feature testable and demonstrable offline.

2. When a model is available, a classifier refines each criterion into a 0-4
   band with a justification. The model only *classifies*; the weighted roll-up
   is arithmetic done here, so two runs over the same document cannot produce
   two different totals for the same set of bands.

If stage 2 is unavailable the result is returned with ``model_assisted=False``
and the UI labels it as heuristic-only rather than presenting it as a full score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import catalog


@dataclass
class CriterionScore:
    criterion_id: str
    name: str
    weight: int
    band: int
    band_label: str
    justification: str
    gap_fix: str = ""
    # True only for the strongest heuristic case (see _heuristic_band's first
    # branch): 3+ distinct signals in a substantive section. That evidence is
    # strong enough that a model call adds no information, only cost, so this
    # criterion is excluded from the model prompt entirely — see
    # ambiguous_criteria() and grader_payload() below.
    heuristic_confident: bool = False

    @property
    def weighted(self) -> float:
        return self.weight * (self.band / 4.0)

    @property
    def is_gap(self) -> bool:
        return self.band <= 2


@dataclass
class SOWScore:
    scores: list[CriterionScore] = field(default_factory=list)
    model_assisted: bool = False
    word_count: int = 0

    @property
    def total(self) -> float:
        earned = sum(score.weighted for score in self.scores)
        available = sum(score.weight for score in self.scores)
        if not available:
            return 0.0
        return round(earned / available * 100, 1)

    @property
    def gaps(self) -> list[CriterionScore]:
        return sorted(
            (s for s in self.scores if s.is_gap), key=lambda s: (s.band, -s.weight)
        )

    @property
    def rating(self) -> str:
        thresholds = catalog.sow_criteria()["thresholds"]
        total = self.total
        if total >= thresholds["strong"]:
            return "Strong"
        if total >= thresholds["acceptable"]:
            return "Acceptable"
        if total >= thresholds["weak"]:
            return "Weak"
        return "Inadequate"

    @property
    def summary(self) -> str:
        gaps = self.gaps
        if not gaps:
            return "No material gaps. Every criterion scored Adequate or better."
        worst = gaps[0]
        return (
            f"{len(gaps)} criteri{'on' if len(gaps) == 1 else 'a'} below Adequate. "
            f"The largest exposure is '{worst.name}', which carries "
            f"{worst.weight}% of the total weight and scored {worst.band_label}."
        )


_TOC_LINE_ENDING = re.compile(r"\t\s*\d{1,4}\s*$")


def _is_toc_occurrence(text_lower: str, idx: int) -> bool:
    """True if the character at ``idx`` sits on a Table-of-Contents line.

    Word's tab-stop TOC fields render as plain text as "<title>\\t<page
    number>" per line once extracted. A keyword's first occurrence is very
    often one of these lines (every section title appears in the ToC before
    it appears as a real heading) rather than the section itself — and a ToC
    line is *not* obviously sparse: title words plus a trailing page number
    can out-count a short, real bulleted section on a naive word count. So
    ToC-shaped lines are excluded from consideration outright rather than
    left to compete on word count.
    """
    line_start = text_lower.rfind("\n", 0, idx) + 1
    line_end = text_lower.find("\n", idx)
    if line_end == -1:
        line_end = len(text_lower)
    return bool(_TOC_LINE_ENDING.search(text_lower[line_start:line_end]))


def _best_window_span(
    text_lower: str, hits: list[str], signals: list[str], span: int = 600
) -> tuple[int, int] | None:
    """Find the (start, end) offsets of the richest window around any
    occurrence of a hit signal, or None if there is no occurrence at all.

    A document's Table of Contents repeats section headings near the top of the
    file, so the *first* occurrence of a keyword is frequently a ToC line, not
    the real section — anchoring there systematically undercounts substance in
    any professionally-formatted document, which is nearly all of them. Instead,
    scan every occurrence of every hit, skip ones sitting on a ToC line, and
    keep the window with the most co-occurring signals, then the most words.

    Offsets (rather than the substring itself) are returned so a caller can
    slice the ORIGINAL-cased text at the same positions — this function only
    sees the lower-cased text used for matching.
    """
    best_span: tuple[int, int] | None = None
    best_score = (-1, -1)
    fallback_span: tuple[int, int] | None = None
    for hit in hits:
        start = 0
        while True:
            idx = text_lower.find(hit, start)
            if idx == -1:
                break
            if fallback_span is None:
                fallback_span = (idx, idx + span)
            if not _is_toc_occurrence(text_lower, idx):
                end = idx + span
                window = text_lower[idx:end]
                score = (
                    sum(1 for signal in signals if signal in window),
                    len(window.split()),
                )
                if score > best_score:
                    best_score, best_span = score, (idx, end)
            start = idx + len(hit)
    # Every occurrence was ToC-shaped (unusual, but possible) — fall back to
    # the first occurrence rather than scoring on an empty window.
    return best_span or fallback_span


def _best_window(
    text_lower: str, hits: list[str], signals: list[str], span: int = 600
) -> str:
    """Text of the richest window — see _best_window_span for the logic."""
    span_bounds = _best_window_span(text_lower, hits, signals, span)
    if span_bounds is None:
        return ""
    start, end = span_bounds
    return text_lower[start:end]


def _heuristic_band(text_lower: str, signals: list[str]) -> tuple[int, str, bool]:
    """Score a criterion from keyword presence and surrounding substance.

    Deliberately conservative. Finding the phrase 'out of scope' proves the
    section exists, not that it is any good, so keyword presence alone never
    scores above Partial. Only density of distinct signals plus enough
    surrounding text lifts a criterion to Adequate.

    Returns ``(band, justification, confident)``. ``confident`` is True only
    for the first branch below (3+ distinct signals with a substantive
    section) — the one case where the heuristic's own evidence is strong
    enough that a model's opinion would add nothing. Every other branch,
    including the other band-3 case, is left non-confident on purpose: those
    are exactly the ambiguous calls a classifier should look at.
    """
    hits = [signal for signal in signals if signal in text_lower]
    if not hits:
        return 0, "No matching language found in the document.", False

    # Measure substance near the richest occurrence, not just the first one.
    window = _best_window(text_lower, hits, signals)
    window_words = len(window.split())

    if len(hits) >= 3 and window_words > 60:
        return (
            3,
            f"Found {len(hits)} related signals with substantive surrounding text.",
            True,
        )
    if len(hits) >= 2 and window_words > 100:
        return (
            3,
            f"Found {len(hits)} related signals with a substantial section around them.",
            False,
        )
    if len(hits) >= 2:
        return (
            2,
            f"Found {len(hits)} related signals, but limited detail around them.",
            False,
        )
    if window_words > 120:
        return 2, "Referenced once, but within a substantial section.", False
    return 1, "Referenced once, with little supporting detail.", False


def score_heuristic(sow_text: str) -> SOWScore:
    """Deterministic pass. No model, no network."""
    spec = catalog.sow_criteria()
    bands = spec["bands"]
    heuristics = spec["heuristics"]
    text_lower = sow_text.lower()

    scores: list[CriterionScore] = []
    for criterion in spec["criteria"]:
        signals = heuristics.get(criterion["id"], [])
        band, justification, confident = _heuristic_band(text_lower, signals)
        scores.append(
            CriterionScore(
                criterion_id=criterion["id"],
                name=criterion["name"],
                weight=criterion["weight"],
                band=band,
                band_label=bands[band]["label"],
                justification=justification,
                gap_fix=criterion["gap_fix"].strip(),
                heuristic_confident=confident,
            )
        )

    return SOWScore(
        scores=scores,
        model_assisted=False,
        word_count=len(re.findall(r"\b\w+\b", sow_text)),
    )


def apply_model_bands(
    score: SOWScore, bands_by_id: dict[str, dict[str, Any]]
) -> SOWScore:
    """Overlay model-assigned bands onto a heuristic score.

    ``bands_by_id`` maps criterion id to ``{"band": int, "justification": str}``,
    normally captured by the ``submit_sow_assessment`` structured-output tool.
    Unknown ids and out-of-range bands are ignored rather than trusted, and the
    arithmetic is redone here — the model never reports a total.
    """
    spec = catalog.sow_criteria()
    band_labels = spec["bands"]
    applied = False

    for criterion_score in score.scores:
        payload = bands_by_id.get(criterion_score.criterion_id)
        if not isinstance(payload, dict):
            continue
        band = payload.get("band")
        if not isinstance(band, int) or not 0 <= band <= 4:
            continue
        criterion_score.band = band
        criterion_score.band_label = band_labels[band]["label"]
        criterion_score.justification = (
            payload.get("justification") or criterion_score.justification
        )
        applied = True

    score.model_assisted = applied
    return score


def criteria_for_prompt() -> list[dict[str, str]]:
    """Compact criteria list to hand a classifier. Weights are withheld
    deliberately so the model cannot optimise the total it never computes."""
    spec = catalog.sow_criteria()
    return [
        {
            "id": criterion["id"],
            "name": criterion["name"],
            "question": criterion["prompt"].strip(),
        }
        for criterion in spec["criteria"]
    ]


def criteria_evidence(sow_text: str, span: int = 600) -> list[dict[str, str]]:
    """Per-criterion evidence windows, instead of handing the model the whole
    document.

    A production run measured this: the grader sent criteria JSON plus
    ``sow_text[:60000]`` (~6K tokens for a real SOW) to the model on every
    single pass, when each criterion only needs the passage(s) relevant to
    it. This reuses the exact hit-scanning/ToC-skipping logic the heuristic
    pass already uses (``_best_window_span``), so the model sees the same
    text the heuristic scored — not a separately-chosen window that could
    disagree with it.

    A criterion with no matching signal in the document gets an empty
    ``window`` — that IS the evidence (there is none), and the model should
    band it 0/Absent rather than being handed unrelated text to guess from.

    Returns one entry per criterion: ``{"id", "name", "window"}``.
    """
    spec = catalog.sow_criteria()
    heuristics = spec["heuristics"]
    text_lower = sow_text.lower()

    evidence: list[dict[str, str]] = []
    for criterion in spec["criteria"]:
        signals = heuristics.get(criterion["id"], [])
        hits = [signal for signal in signals if signal in text_lower]
        window = ""
        if hits:
            span_bounds = _best_window_span(text_lower, hits, signals, span)
            if span_bounds is not None:
                start, end = span_bounds
                # Slice the ORIGINAL-cased text at the offsets found on the
                # lower-cased copy, so the model sees real capitalisation
                # when it quotes the document back in its justification.
                window = sow_text[start:end]
        evidence.append(
            {"id": criterion["id"], "name": criterion["name"], "window": window}
        )
    return evidence


def ambiguous_criteria(score: SOWScore) -> list[str]:
    """Criterion ids the heuristic pass was NOT confident about.

    These are the only ones worth spending a model call on — see
    CriterionScore.heuristic_confident for what "confident" means and why.
    """
    return [c.criterion_id for c in score.scores if not c.heuristic_confident]


def grader_payload(
    sow_text: str, score: SOWScore, span: int = 600
) -> list[dict[str, str]]:
    """Criteria + evidence to hand the model classifier.

    Combines two cost cuts measured against a real SOW review:
    - Only ambiguous criteria are included at all (heuristic-confident ones
      are excluded — see ``ambiguous_criteria``).
    - Each included criterion carries its own evidence window instead of the
      full document (see ``criteria_evidence``).

    Returns an empty list when every criterion was heuristic-confident —
    callers should treat that as "no model call needed", not "call anyway".
    """
    ambiguous = set(ambiguous_criteria(score))
    if not ambiguous:
        return []
    windows = {item["id"]: item["window"] for item in criteria_evidence(sow_text, span)}
    spec = catalog.sow_criteria()
    return [
        {
            "id": criterion["id"],
            "name": criterion["name"],
            "question": criterion["prompt"].strip(),
            "evidence": windows.get(criterion["id"], ""),
        }
        for criterion in spec["criteria"]
        if criterion["id"] in ambiguous
    ]

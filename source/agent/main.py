"""POC Validator — AgentCore Runtime entrypoint.

Five phases, plus two optional ones. Only phases 1 and 4 involve a model as
part of the standard review; 2, 3 and 5 are deterministic Python over the
shared design graph. That split is deliberate and carried over from ADR 0014
in the event-driven-claims-agent sample: the model is used where judgement is
needed (reading a diagram, banding prose) and kept away from anything a
reviewer would take at face value (findings, arithmetic, source URLs).

    Phase 1  Intake / diagram extraction   Sonnet, vision   → design graph
             ⤷ confirmation gate — nothing proceeds until the caller confirms
    Phase 2  Validation                     deterministic    → findings
    Phase 3  Pricing                        deterministic    → baseline + premium
    Phase 4  SOW scoring                    Haiku + weights  → score + gaps
    Phase 5  Recommendations                allowlist filter → AWS-only reading
    Phase 6a What-if pricing (optional)    Haiku + sandbox  → docs/decisions/0010
    Phase 6b FAQ knowledge search (optional) vector search  → docs/decisions/0011
"""

import base64
import dataclasses
import json
import re
import sys
import uuid
from pathlib import Path

from bedrock_agentcore.identity.auth import requires_access_token
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from config import (
    AGENT_MODEL_ID,
    COST_RECONCILIATION_TOLERANCE,
    FAST_MODEL_ID,
    GATEWAY_CREDENTIAL_PROVIDER,
    GATEWAY_OAUTH_SCOPES,
    GATEWAY_URL,
    REQUIRE_EXTRACTION_CONFIRMATION,
)
from mcp.client.streamable_http import streamablehttp_client
from memory.session import get_memory_session_manager
from strands import Agent
from strands.hooks.events import BeforeToolCallEvent
from strands.interventions import Deny, InterventionHandler, Proceed
from strands.models.bedrock import BedrockModel
from strands.tools.mcp import MCPClient
from tools.faq_search import search_faq
from tools.structured_output import (
    get_last_extraction,
    get_last_sow_bands,
    reset_state,
    submit_extraction,
    submit_sow_assessment,
)
from tools.what_if_pricing import run_what_if

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import costs, diagrams, engine, sow
from core.models import Severity

app = BedrockAgentCoreApp()
log = app.logger

EXTRACTION_PROMPT = """You are an AWS architecture diagram reader.

You will be shown an architecture diagram. Your only job is to report what is on
it — the AWS services, and the connections between them.

Rules:
- Report only what you can see. Do not add services that "should" be there.
- If a box is ambiguous, report the label as written and note the ambiguity.
- Follow arrow direction for edges. Where there are no arrows, infer direction
  from data flow and say so in your notes.
- Do not evaluate the architecture. Do not offer opinions, findings or advice.
  A separate deterministic stage does that, and your speculation would corrupt it.
- You MUST finish by calling the submit_extraction tool exactly once.
"""

SOW_EXTRACTION_PROMPT = """You extract AWS services from a Scope of Work document.

Rules:
- Report ONLY services the document explicitly names. Do not add services that
  "should" be there.
- Where the document describes a data flow between two named services, report
  it as an edge.
- Do not evaluate, price, or advise — a separate deterministic stage does that,
  and your speculation would corrupt it.
- You MUST finish by calling the submit_extraction tool exactly once.
"""

SOW_PROMPT = """You are grading a Scope of Work document against fixed criteria.

For each criterion you will be given an id and a question. Assign a band:
  0 Absent      — not present at all
  1 Mentioned   — referenced with no substance
  2 Partial     — present but incomplete or ambiguous
  3 Adequate    — clear and usable as written
  4 Strong      — explicit, specific and measurable

Rules:
- Judge only what the document says. Do not credit intent you infer.
- Boilerplate ("performed in a professional manner") is band 1, not band 3.
- Justify each band in one sentence, quoting or closely paraphrasing the document.
- Do NOT compute a total. Weighting happens outside the model and any total you
  produce will be discarded.
- You MUST finish by calling the submit_sow_assessment tool exactly once.
"""

_extractor = None
_mcp_client = None

# MEASURED (production run): the SOW grader's tool-using agent retried
# submit_sow_assessment 14 times on Nova, each retry resending the whole
# context, and only stopped once the response hit the token ceiling — that is
# what produced "No services extracted" downstream. Strands' Agent has no
# max_iterations knob for a single agent (that only exists on the multiagent
# Swarm), so this is the equivalent guard, implemented as an intervention.
SOW_GRADER_MAX_TOOL_ATTEMPTS = 2


class _ToolAttemptCap(InterventionHandler):
    """Denies a tool call once it has been attempted more than N times.

    Counts EVERY before_tool_call this handler sees (not just failures) —
    the agent that motivated this only calls one tool (submit_sow_assessment),
    so "attempts" and "attempts at that tool" are the same thing here. A
    handler instance must be built fresh per Agent invocation: it is
    stateful, and reusing one across calls would let attempts accumulate
    across unrelated documents instead of capping each grading pass on its
    own.
    """

    name = "tool-attempt-cap"

    def __init__(self, max_attempts: int = SOW_GRADER_MAX_TOOL_ATTEMPTS, logger=None):
        self._max_attempts = max_attempts
        self._attempts = 0
        self._logger = logger

    def before_tool_call(self, event: BeforeToolCallEvent, **_kwargs):
        self._attempts += 1
        if self._attempts <= self._max_attempts:
            return Proceed()
        if self._logger is not None:
            self._logger.warning(
                "Tool-attempt cap (%d) tripped on %r — stopping the loop",
                self._max_attempts,
                event.tool_use.get("name"),
            )
        return Deny(reason=f"Stopped after {self._max_attempts} tool attempts.")


def load_model(fast: bool = False) -> BedrockModel:
    """Cost routing: Haiku for SOW banding (classification), Sonnet for vision."""
    return BedrockModel(model_id=FAST_MODEL_ID if fast else AGENT_MODEL_ID)


@requires_access_token(
    provider_name=GATEWAY_CREDENTIAL_PROVIDER,
    auth_flow="M2M",
    scopes=GATEWAY_OAUTH_SCOPES.replace(",", " ").split(),
)
def _build_mcp_client(*, access_token: str) -> MCPClient:
    """MCPClient for the Gateway, with Identity-managed OAuth.

    The decorator handles token acquisition from the AgentCore Identity token
    vault, caching and refresh — no secrets in env vars or code.
    """

    def _transport():
        headers = {"Authorization": f"Bearer {access_token}"}
        return streamablehttp_client(GATEWAY_URL, headers=headers)

    return MCPClient(_transport)


def get_mcp_client():
    """Gateway client, or None. None is a supported state, not an error."""
    global _mcp_client
    if _mcp_client is None:
        if not GATEWAY_URL:
            log.warning("GATEWAY_URL not configured — documentation lookup unavailable")
            return None
        try:
            _mcp_client = _build_mcp_client()
        except Exception as exc:  # noqa: BLE001 — Gateway/Identity unavailable degrades to no tools, not a crash
            log.warning("Failed to build MCP client (Identity auth): %s", exc)
            return None
    return _mcp_client


def get_extractor(session_manager=None):
    global _extractor
    tools = [submit_extraction]
    mcp = get_mcp_client()
    if mcp:
        tools.insert(0, mcp)
    if session_manager is not None:
        return Agent(
            model=load_model(),
            system_prompt=EXTRACTION_PROMPT,
            tools=tools,
            session_manager=session_manager,
        )
    if _extractor is None:
        _extractor = Agent(
            model=load_model(), system_prompt=EXTRACTION_PROMPT, tools=tools
        )
    return _extractor


def get_sow_grader():
    """SOW grader gets no Gateway access — it reads a document, nothing else.

    Built fresh on every call, unlike get_extractor's cached agent: the
    tool-attempt cap below is per-instance state that must count attempts
    within THIS grading pass only (see _ToolAttemptCap).
    """
    return Agent(
        model=load_model(fast=True),
        system_prompt=SOW_PROMPT,
        tools=[submit_sow_assessment],
        interventions=[_ToolAttemptCap(logger=log)],
    )


def _decode_diagram(payload: dict):
    """Return a Strands image content block from a base64 diagram, or None."""
    raw = payload.get("diagram_base64")
    if not raw:
        return None
    fmt = (payload.get("diagram_format") or "png").lower().lstrip(".")
    if fmt == "jpg":
        fmt = "jpeg"
    if fmt not in {"png", "jpeg", "gif", "webp"}:
        log.warning("Unsupported diagram format %r — skipping extraction", fmt)
        return None
    try:
        return {"image": {"format": fmt, "source": {"bytes": base64.b64decode(raw)}}}
    except Exception as exc:  # noqa: BLE001 — malformed base64 degrades to "no image", never a crash
        log.warning("Could not decode diagram: %s", exc)
        return None


def _normalise_payload(payload):
    """Unwrap the {"prompt": "<json>"} shape that `agentcore dev` produces."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {"prompt": payload}
    if "prompt" in payload and "description" not in payload:
        inner = payload["prompt"]
        if isinstance(inner, str):
            try:
                parsed = json.loads(inner)
                if isinstance(parsed, dict):
                    payload = parsed
            except (json.JSONDecodeError, TypeError):
                payload.setdefault("description", inner)
    return payload


def _json_from_text(text: str):
    """Best-effort JSON recovery from a plain-text model reply (fences, prose).

    Fallback path for models whose tool-use streaming is unreliable (observed
    intermittently with Nova: 'Model produced invalid sequence as part of
    ToolUse'). Plain text generation is stable, so asking for bare JSON and
    parsing it here recovers the run instead of degrading."""
    match = re.search(r"[\[{][\s\S]*[\]}]", text)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


async def _plain_json_completion(model, system_prompt: str, user_input: str):
    """Run a tool-less agent and return its reply parsed as JSON (or None)."""
    agent = Agent(model=model, system_prompt=system_prompt, tools=[])
    chunks = []
    async for event in agent.stream_async(user_input):
        if "data" in event and isinstance(event["data"], str):
            chunks.append(event["data"])
    return _json_from_text("".join(chunks))


SOW_EXTRACTION_JSON_PROMPT = SOW_EXTRACTION_PROMPT.replace(
    "- You MUST finish by calling the submit_extraction tool exactly once.",
    '- Respond with ONLY a JSON object, no prose and no code fences:\n'
    '  {"services": ["..."], "edges": [["a","b"]], "unmatched": ["..."], "notes": "..."}',
)

SOW_BANDS_JSON_PROMPT = SOW_PROMPT.replace(
    "- You MUST finish by calling the submit_sow_assessment tool exactly once.",
    '- Respond with ONLY a JSON array, no prose and no code fences:\n'
    '  [{"id": "SOW-01", "band": 0, "justification": "..."}, ...]',
)


def _prefers_plain_json_first(model_id: str) -> bool:
    """Which SOW-banding path to try FIRST for this model family.

    MEASURED (production run): with a Nova model configured as FAST_MODEL_ID,
    the tool-using get_sow_grader() agent failed the JSON-array tool schema on
    14 consecutive attempts ("Invalid header padding" / "persistent issues
    with JSON parsing") before the plain-JSON fallback ever got a chance to
    run — each failed attempt resent the full grading context. Nova reliably
    SUCCEEDS at bare JSON and reliably FAILS the tool-call schema, so for Nova
    the "fallback" must be the first (and normally only) attempt, not a
    last resort reached after burning a budget of failed tool calls. Every
    other model family this sample is configured against calls tools
    reliably, so they keep the original tool-first order.
    """
    return "nova" in model_id.lower()


async def _tool_grade_sow(grader_input: str) -> tuple[str, dict | None]:
    """Tool-based SOW grading via get_sow_grader(). Returns (streamed text
    the caller should show, bands-by-id or None)."""
    chunks: list[str] = []
    try:
        grader = get_sow_grader()
        async for event in grader.stream_async(grader_input):
            if "data" in event and isinstance(event["data"], str):
                chunks.append(event["data"])
        return "".join(chunks), (get_last_sow_bands() or None)
    except Exception as exc:  # noqa: BLE001 — model access is expected to be blocked in this account
        log.warning("SOW model pass unavailable, using heuristic floor: %s", exc)
        return "".join(chunks), None


async def _plain_grade_sow(grader_input: str) -> dict | None:
    """Plain-JSON SOW grading (no tool schema). Returns bands-by-id or None.

    Same flaky-tool-use recovery path as SOW-text extraction: ask for bare
    JSON and parse it here rather than trust tool-use streaming."""
    try:
        data = await _plain_json_completion(
            load_model(fast=True), SOW_BANDS_JSON_PROMPT, grader_input
        )
    except Exception as exc:  # noqa: BLE001 — heuristic floor remains the final fallback
        log.warning("SOW banding JSON fallback failed: %s", exc)
        return None
    if not isinstance(data, list):
        return None
    return {
        str(item.get("id")): item
        for item in data
        if isinstance(item, dict) and item.get("id")
    }


async def _grade_sow(
    grader_input: str,
    fast_model_id: str,
    *,
    tool_grade=_tool_grade_sow,
    plain_grade=_plain_grade_sow,
) -> tuple[str, dict | None]:
    """Run the tool-based and plain-JSON SOW graders in whichever order the
    configured fast model reliably succeeds at first — see
    _prefers_plain_json_first for why. Falls back to the other path only if
    the first returns nothing usable. Returns (text to show, bands-by-id).

    ``tool_grade``/``plain_grade`` are injectable so this ordering rule is
    unit-testable without an Agent, a model, or network access.
    """
    if _prefers_plain_json_first(fast_model_id):
        bands = await plain_grade(grader_input)
        if bands:
            return "", bands
        return await tool_grade(grader_input)

    text, bands = await tool_grade(grader_input)
    if bands:
        return text, bands
    bands = await plain_grade(grader_input)
    return text, bands


def _confirmation_payload(extraction) -> dict:
    """The awaiting_confirmation contract (ADR 0002), shared by the vision and
    SOW-text extraction gates so both branches emit the identical shape."""
    return {
        "status": "awaiting_confirmation",
        "extraction": {
            "services": extraction.services,
            "edges": [list(edge) for edge in extraction.edges],
            "unmatched": extraction.unmatched,
            "notes": extraction.notes,
        },
    }


@app.entrypoint
async def invoke(payload, context):
    """Run a POC validation. Streams phase progress, ends with a JSON result."""
    payload = _normalise_payload(payload)
    reset_state()

    description = payload.get("description", "")
    segment = payload.get("segment", "enterprise")
    industry = payload.get("industry", "generic")
    region = payload.get("region", "ap-south-1")
    services = payload.get("services") or []
    edges = [tuple(edge) for edge in (payload.get("edges") or [])]
    sow_text = payload.get("sow_text", "")
    confirmed = bool(payload.get("extraction_confirmed", False))

    actor_id = payload.get("partner_id") or payload.get("user_id") or "anonymous"
    session_id = f"poc-{actor_id}-{uuid.uuid4().hex[:12]}"

    session_manager = None
    try:
        session_manager = get_memory_session_manager(session_id, actor_id)
    except Exception as exc:  # noqa: BLE001 — Memory unavailable degrades to no recall, not a crash
        log.warning("Memory unavailable (running without recall): %s", exc)

    # ── Phase 1: diagram extraction ──────────────────────────────────────────
    # Source diagrams parse exactly, so they skip both the model and the
    # confirmation gate. Only images need vision, and only vision needs a human
    # to check the result. See docs/decisions/0007.
    diagram_name = payload.get("diagram_filename", "")
    diagram_text = payload.get("diagram_text", "")
    if diagram_text and diagrams.is_deterministic(diagram_name or ".mmd"):
        yield "## Phase 1 · Parsing the diagram source\n\n"
        parsed = diagrams.parse(diagram_name or "diagram.mmd", diagram_text)
        if not services:
            services = parsed.services
        if not edges:
            edges = parsed.edges
        yield f"{parsed.notes}\n\n"
        if parsed.unmatched:
            yield (
                "**Not recognised, and therefore not included:** "
                + ", ".join(parsed.unmatched)
                + "\n\n"
            )

    image_block = _decode_diagram(payload)
    if image_block is not None:
        yield "## Phase 1 · Reading the diagram\n\n"
        try:
            extractor = get_extractor(session_manager=session_manager)
            message = [
                image_block,
                {
                    "text": "Identify every AWS service in this architecture diagram "
                    "and the connections between them, then call submit_extraction."
                },
            ]
            async for event in extractor.stream_async(message):
                if "data" in event and isinstance(event["data"], str):
                    yield event["data"]
        except Exception as exc:  # noqa: BLE001 — model access is expected to be blocked in this account
            log.warning("Diagram extraction failed: %s", exc)
            yield f"\n\nDiagram extraction unavailable: {exc}\n"

        extraction = engine.extraction_from_raw(get_last_extraction())

        if not services:
            services = extraction.services
        if not edges:
            edges = extraction.edges

        if extraction.unmatched:
            yield (
                "\n\n**Not recognised:** "
                + ", ".join(extraction.unmatched)
                + " — confirm or correct these before the review runs.\n"
            )

        if REQUIRE_EXTRACTION_CONFIRMATION and not confirmed:
            # Correctness gate. Findings generated against a misread diagram
            # would describe a design the partner never proposed.
            yield (
                "\n\n---\n**Confirmation required.** Review the extraction below, "
                "then resubmit with `extraction_confirmed: true`.\n\n"
            )
            yield json.dumps(_confirmation_payload(extraction), indent=2)
            return

    # ── Phase 1c: SOW-text service extraction ────────────────────────────────
    # Runs only when neither the caller nor a diagram supplied services but an
    # SOW document is present. Prose is read by a model, so the result goes
    # through the same confirmation gate as vision extraction (ADR 0002). A
    # confirmed resubmission echoes the services back, making this branch — and
    # the model — skip entirely on the second call.
    if not services and sow_text.strip():
        yield "## Phase 1 · Extracting services from the SOW\n\n"
        try:
            sow_extractor = Agent(
                model=load_model(),
                system_prompt=SOW_EXTRACTION_PROMPT,
                tools=[submit_extraction],
            )
            async for event in sow_extractor.stream_async(
                "Identify every AWS service named in this Scope of Work and the "
                "integrations between them, then call submit_extraction.\n\n"
                "Document:\n" + sow_text[:60000]
            ):
                if "data" in event and isinstance(event["data"], str):
                    yield event["data"]
        except Exception as exc:  # noqa: BLE001 — model access is expected to be blocked in this account
            log.warning("SOW service extraction failed: %s", exc)
            yield f"\n\nSOW service extraction unavailable: {exc}\n"

        extraction = engine.extraction_from_raw(get_last_extraction())
        if not extraction.services:
            # Tool path produced nothing (flaky tool-use streaming) — retry
            # once asking for bare JSON and parse it ourselves.
            yield "\n\nRetrying extraction without tool calling…\n"
            try:
                data = await _plain_json_completion(
                    load_model(), SOW_EXTRACTION_JSON_PROMPT,
                    "Document:\n" + sow_text[:60000],
                )
                if isinstance(data, dict):
                    extraction = engine.extraction_from_raw(data)
            except Exception as exc:  # noqa: BLE001 — fallback failure degrades to the no-services gate below
                log.warning("SOW extraction JSON fallback failed: %s", exc)
        services = extraction.services
        if not edges:
            edges = extraction.edges

        if extraction.unmatched:
            yield (
                "\n\n**Not recognised:** "
                + ", ".join(extraction.unmatched)
                + " — these will NOT be part of the review.\n"
            )

        if services and REQUIRE_EXTRACTION_CONFIRMATION and not confirmed:
            yield (
                "\n\n---\n**Confirmation required.** Review the extraction below, "
                "then resubmit with the confirmed `services` list and "
                "`extraction_confirmed: true`.\n\n"
            )
            yield json.dumps(_confirmation_payload(extraction), indent=2)
            return

    if not services:
        yield json.dumps(
            {"status": "error", "message": "No services supplied and none extracted."}
        )
        return

    # ── Phase 4a: SOW banding (before validation so it can feed the report) ──
    # Minimum evidence to trust the per-criterion windows below. Below this,
    # an oddly formatted SOW may have starved every window of matches even
    # though real content exists elsewhere — the safety valve falls back to a
    # truncated full document rather than grade the model on scraps.
    MIN_EVIDENCE_CHARS = 500

    sow_score = None
    if sow_text.strip():
        yield "\n\n---\n## Phase 4 · Scoring the Scope of Work\n\n"
        sow_score = sow.score_heuristic(sow_text)

        # Only criteria the heuristic pass was NOT already confident about
        # are worth a model call — see CriterionScore.heuristic_confident.
        ambiguous = sow.ambiguous_criteria(sow_score)
        bands = None
        if not ambiguous:
            yield "Heuristic pass was confident on every criterion — skipping the model.\n"
        else:
            criteria_payload = sow.grader_payload(sow_text, sow_score)
            evidence_chars = sum(len(c["evidence"]) for c in criteria_payload)
            if evidence_chars >= MIN_EVIDENCE_CHARS:
                grader_input = (
                    "Criteria, each with the evidence window found for it in "
                    "the document. Judge only what is shown; an empty "
                    "evidence field means no matching language was found and "
                    "should band 0/Absent:\n"
                    + json.dumps(criteria_payload, indent=2)
                )
            else:
                grader_input = (
                    "Criteria:\n"
                    + json.dumps(
                        [
                            c
                            for c in sow.criteria_for_prompt()
                            if c["id"] in set(ambiguous)
                        ],
                        indent=2,
                    )
                    + "\n\nDocument:\n"
                    + sow_text[:60000]
                )

            text, bands = await _grade_sow(grader_input, FAST_MODEL_ID)
            if text:
                yield text

        if bands:
            sow_score = sow.apply_model_bands(sow_score, bands)
        elif ambiguous:
            yield "\n\nModel grading unavailable — heuristic floor only.\n"

    # ── Phases 2, 3, 5: deterministic ────────────────────────────────────────
    yield "\n\n---\n## Phases 2, 3 & 5 · Validation, pricing and recommendations\n\n"

    graph = engine.graph_from_selection(
        segment_id=segment,
        industry_id=industry,
        region=region,
        description=description,
        service_ids=services,
        edges=edges,
        overrides=payload.get("config_overrides") or {},
    )
    report = engine.validate(graph, sow_score)

    # ── Cost reconciliation (COST-01 / COST-02) ─────────────────────────────
    # Does the SOW's own stated monthly total resemble the estimate the
    # pricing phase just computed? Findings are appended into the report
    # BEFORE counts/verdict are read below so a sharp divergence weighs on
    # the verdict exactly like any other finding — see core/costs.py.
    reconciliation = costs.reconcile(
        sow_text, report.cost.total, tolerance=COST_RECONCILIATION_TOLERANCE
    )
    cost_findings, cost_passed = costs.build_findings(reconciliation)
    report.findings.extend(cost_findings)

    verdict, reasoning = report.verdict
    yield f"**{verdict}** — {reasoning}\n\n"

    result = {
        "status": "complete",
        "session_id": session_id,
        "verdict": {"result": verdict, "reasoning": reasoning},
        "counts": {severity.value: report.count(severity) for severity in Severity},
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "title": finding.title,
                "pillar": finding.pillar,
                "source": finding.source_label,
                "rationale": finding.rationale,
                "remediation": finding.remediation,
                "doc_url": finding.doc_url,
            }
            for finding in report.sorted_findings
        ],
        "conflicts": [
            {
                "attribute": conflict.attribute,
                "node": conflict.node_name,
                "segment_position": conflict.segment_position,
                "industry_position": conflict.industry_position,
                "resolution": conflict.resolution,
            }
            for conflict in report.conflicts
        ],
        "integrations": [
            {
                "from": edge.source,
                "to": edge.target,
                "type": edge.edge_type.value,
                "pattern": edge.pattern,
                "note": edge.note,
            }
            for edge in report.graph.edges
        ],
        "cost": {
            "baseline": report.cost.baseline,
            "compliance_premium": report.cost.premium,
            "total": report.cost.total,
            "currency": report.cost.currency,
            "region": report.cost.region,
            "as_of": report.cost.as_of,
            "lines": [dataclasses.asdict(line) for line in report.cost.lines],
            "reconciliation": {
                "stated_monthly_total": reconciliation.stated.amount,
                "stated_candidates": reconciliation.stated.candidates,
                "ambiguous": reconciliation.stated.ambiguous,
                "estimated_monthly_total": reconciliation.estimated,
                "ratio": (
                    None
                    if reconciliation.ratio in (None, float("inf"))
                    else reconciliation.ratio
                ),
                "tolerance": reconciliation.tolerance,
                "within_tolerance": reconciliation.within_tolerance,
                "unpriceable_services": reconciliation.unpriceable_services,
            },
        },
        "passed_checks": cost_passed,
        "recommendations": [
            {
                "title": resource.title,
                "kind": resource.kind_label,
                "url": resource.url,
                "summary": resource.summary,
                "why": reason,
            }
            for resource, reason in report.recommendations
        ],
        "evidence": report.evidence,
        "gateway_available": get_mcp_client() is not None,
    }

    if sow_score is not None:
        result["sow"] = {
            "score": sow_score.total,
            "rating": sow_score.rating,
            "model_assisted": sow_score.model_assisted,
            "summary": sow_score.summary,
            "criteria": [
                {
                    "id": criterion.criterion_id,
                    "name": criterion.name,
                    "weight": criterion.weight,
                    "band": criterion.band,
                    "band_label": criterion.band_label,
                    "justification": criterion.justification,
                    "fix": criterion.gap_fix if criterion.is_gap else "",
                }
                for criterion in sow_score.scores
            ],
        }

    # ── Phase 6a: what-if pricing (optional, Code Interpreter) ──────────────
    # Only runs if the caller asks a question. See docs/decisions/0010 for
    # why this needs a model call this account's Marketplace restriction may
    # block, and why that's stated in the response rather than hidden.
    what_if_question = payload.get("what_if_question", "").strip()
    if what_if_question:
        yield "\n\n---\n## Phase 6a · What-if pricing\n\n"
        whatif = run_what_if(what_if_question, result["cost"]["lines"])
        if whatif["status"] == "unavailable":
            yield f"What-if pricing unavailable: {whatif['reason']}\n"
        else:
            yield "Ran a model-authored, sandbox-executed recomputation — see `what_if.code` in the result for exactly what ran.\n"
        result["what_if"] = whatif

    # ── Phase 6b: FAQ knowledge search (optional, Knowledge Base) ───────────
    # Only runs if the caller asks. See docs/decisions/0011 for why this is a
    # Knowledge Base rather than a Memory namespace.
    faq_query = payload.get("faq_query", "").strip()
    if faq_query:
        yield "\n\n---\n## Phase 6b · FAQ knowledge search\n\n"
        faq = search_faq(faq_query)
        if faq["status"] == "unavailable":
            yield f"FAQ search unavailable: {faq['reason']}\n"
        else:
            yield f"Found {len(faq['results'])} matching FAQ entries.\n"
        result["faq"] = faq

    yield json.dumps(result, indent=2)


if __name__ == "__main__":
    app.run()

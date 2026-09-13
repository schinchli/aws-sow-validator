"""Tests for core/costs.py — does the SOW's own stated price reconcile with
the independently computed pricing estimate?

Mirrors tests/test_pocvalidator.py's import setup (source/agent as the
`agent` package) since core/costs.py lives in source/agent/core/.
"""

import importlib
import os
import sys
import unittest.mock as mock
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("POC_VALIDATOR_ROOT", str(ROOT))
sys.path.insert(0, str(ROOT / "source"))

from agent.core import costs, engine  # noqa: E402
from agent.core.models import Severity  # noqa: E402

# The real numbers from the customer SOW that motivated this module.
STATED_REAL = 10501.18
ESTIMATED_REAL = 427.64


# ── Stated-total extraction ──────────────────────────────────────────────────


class TestExtractStatedTotal:
    def test_table_layout_row(self):
        """Cells arrive as 'Label | $Amount' on one line — no sentence around it."""
        text = (
            "Cost Summary\n"
            "Line Item | Monthly\n"
            "Compute | $120.00\n"
            "Total Estimated Monthly Cost | $10,501.18\n"
        )
        stated = costs.extract_stated_monthly_total(text)
        assert stated.amount == 10501.18
        assert not stated.ambiguous

    def test_per_month_shorthand(self):
        text = "Steady-state pricing comes to $2,030.81/mo once training completes."
        stated = costs.extract_stated_monthly_total(text)
        assert stated.amount == 2030.81
        assert not stated.ambiguous

    def test_annual_figure_divided_by_twelve(self):
        text = "Commercial terms: Annual: $24,000 for the managed service tier."
        stated = costs.extract_stated_monthly_total(text)
        assert stated.amount == 2000.0
        assert not stated.ambiguous

    def test_no_figure_at_all(self):
        text = "This SOW describes a serverless data pipeline with no pricing section."
        stated = costs.extract_stated_monthly_total(text)
        assert stated.amount is None
        assert not stated.ambiguous
        assert stated.candidates == []

    def test_conflicting_figures_are_ambiguous_not_guessed(self):
        """Two different labelled totals in the same tier — must not silently
        pick one."""
        text = (
            "Total Estimated Monthly Cost | $4,200.00\n"
            "Total Monthly Cost (revised) | $4,650.00\n"
        )
        stated = costs.extract_stated_monthly_total(text)
        assert stated.amount is None
        assert stated.ambiguous
        assert stated.candidates == [4200.00, 4650.00]


# ── Reconciliation outcomes ───────────────────────────────────────────────────


class TestReconcile:
    def test_real_customer_divergence_is_high_with_both_numbers_and_ratio(self):
        text = f"Total Estimated Monthly Cost | ${STATED_REAL:,.2f}\n"
        result = costs.reconcile(text, ESTIMATED_REAL)
        assert result.stated.amount == STATED_REAL
        assert result.within_tolerance is False
        assert result.ratio == pytest.approx(24.56, abs=0.05)

        findings, passed = costs.build_findings(result)
        assert not passed
        high = [f for f in findings if f.rule_id == costs.RULE_RECONCILIATION]
        assert len(high) == 1
        assert high[0].severity is Severity.HIGH
        assert f"${STATED_REAL:,.2f}" in high[0].rationale
        assert f"${ESTIMATED_REAL:,.2f}" in high[0].rationale
        assert "24.6x" in high[0].rationale

    def test_agreement_within_tolerance_is_a_passed_check_not_a_finding(self):
        text = "Total Estimated Monthly Cost | $2,050.00\n"
        result = costs.reconcile(text, 2000.00, tolerance=0.10)
        assert result.within_tolerance is True

        findings, passed = costs.build_findings(result)
        assert not [f for f in findings if f.rule_id == costs.RULE_RECONCILIATION]
        assert len(passed) == 1
        assert passed[0]["rule_id"] == costs.RULE_RECONCILIATION
        assert "$2,050.00" in passed[0]["detail"]
        assert "$2,000.00" in passed[0]["detail"]

    def test_custom_tolerance_changes_the_verdict_on_the_same_numbers(self):
        text = "Total Estimated Monthly Cost | $2,400.00\n"
        loose = costs.reconcile(text, 2000.00, tolerance=0.30)
        tight = costs.reconcile(text, 2000.00, tolerance=0.10)
        assert loose.within_tolerance is True
        assert tight.within_tolerance is False

    def test_no_stated_figure_is_medium(self):
        text = "This SOW has no pricing section at all."
        result = costs.reconcile(text, 500.00)
        assert result.stated.amount is None

        findings, passed = costs.build_findings(result)
        assert not passed
        assert len(findings) == 1
        assert findings[0].rule_id == costs.RULE_RECONCILIATION
        assert findings[0].severity is Severity.MEDIUM
        assert "$500.00" in findings[0].rationale

    def test_ambiguous_stated_figure_is_medium_and_names_every_candidate(self):
        text = (
            "Total Estimated Monthly Cost | $4,200.00\n"
            "Total Monthly Cost (revised) | $4,650.00\n"
        )
        result = costs.reconcile(text, 4300.00)
        findings, passed = costs.build_findings(result)
        assert not passed
        assert len(findings) == 1
        assert findings[0].severity is Severity.MEDIUM
        assert "$4,200.00" in findings[0].rationale
        assert "$4,650.00" in findings[0].rationale


# ── Coverage gaps (COST-02) ───────────────────────────────────────────────────


class TestUnpriceableServices:
    def test_named_bedrock_model_detected_verbatim(self):
        text = (
            "Inference runs on Claude Opus 4.5 via Amazon Bedrock for complex "
            "reasoning and Claude Haiku for high-volume classification."
        )
        found = costs.find_unpriceable_services(text)
        assert "Claude Opus 4.5" in found
        assert "Claude Haiku" in found

    def test_uncatalogued_service_detected(self):
        text = "Model training uses Amazon SageMaker with spot instances."
        found = costs.find_unpriceable_services(text)
        assert "Amazon SageMaker" in found

    def test_clean_text_finds_nothing(self):
        text = "The platform uses AWS Lambda, Amazon API Gateway and Amazon RDS."
        assert costs.find_unpriceable_services(text) == []

    def test_real_scenario_incomplete_reconciliation_finding(self):
        """The concrete gap this module was built for: Claude Opus 4.5/4.6 on
        Bedrock accounts for ~$10,395 of the stated total, and the catalogue's
        flat per-token Bedrock rate has no notion of which model is running."""
        text = (
            f"Total Estimated Monthly Cost | ${STATED_REAL:,.2f}\n"
            "Generative AI inference uses Claude Opus 4.5 on Amazon Bedrock for "
            "complex reasoning tasks (~$10,395/mo of the total) and Claude Haiku "
            "for lightweight classification."
        )
        result = costs.reconcile(text, ESTIMATED_REAL)
        assert "Claude Opus 4.5" in result.unpriceable_services

        findings, _ = costs.build_findings(result)
        coverage = [f for f in findings if f.rule_id == costs.RULE_COVERAGE]
        assert len(coverage) == 1
        assert coverage[0].severity is Severity.MEDIUM
        assert "Claude Opus 4.5" in coverage[0].rationale
        # The divergence finding still fires alongside it — the coverage gap
        # only explains part of the story, it doesn't excuse silence on the
        # rest.
        assert any(f.rule_id == costs.RULE_RECONCILIATION for f in findings)

    def test_no_coverage_finding_without_a_stated_total(self):
        """COST-02 only makes sense once there is a stated figure to compare
        against — otherwise there is nothing for the gap to be incomplete
        relative to."""
        text = "Inference uses Claude Opus 4.5 on Amazon Bedrock."
        result = costs.reconcile(text, ESTIMATED_REAL)
        assert result.stated.amount is None
        findings, _ = costs.build_findings(result)
        assert not [f for f in findings if f.rule_id == costs.RULE_COVERAGE]


# ── Flows into counts/verdict like any other finding ────────────────────────


def _validated_report(sow_text, estimated_override=None):
    graph = engine.graph_from_selection(
        "enterprise", "generic", "ap-south-1", "test",
        ["lambda", "apigateway"], [],
    )
    report = engine.validate(graph)
    estimated = (
        estimated_override if estimated_override is not None else report.cost.total
    )
    result = costs.reconcile(sow_text, estimated)
    findings, passed = costs.build_findings(result)
    report.findings.extend(findings)
    return report, passed


class TestFlowsIntoCountsAndVerdict:
    def test_high_finding_raises_high_count_and_flips_verdict(self):
        clean_report, _ = _validated_report(
            "Total Estimated Monthly Cost | $1.00\n", estimated_override=1.0
        )
        before_high = clean_report.count(Severity.HIGH)

        text = f"Total Estimated Monthly Cost | ${STATED_REAL:,.2f}\n"
        report, _ = _validated_report(text, estimated_override=ESTIMATED_REAL)
        after_high = report.count(Severity.HIGH)

        assert after_high == before_high + 1
        rule_ids = {f.rule_id for f in report.findings}
        assert costs.RULE_RECONCILIATION in rule_ids

        verdict, reasoning = report.verdict
        assert verdict in {"Conditionally ready", "Needs work", "Not ready"}

    def test_passed_check_produced_when_reconciled(self):
        report, passed = _validated_report(
            "Total Estimated Monthly Cost | $100.00\n", estimated_override=100.00
        )
        assert any(p["rule_id"] == costs.RULE_RECONCILIATION for p in passed)
        assert costs.RULE_RECONCILIATION not in {f.rule_id for f in report.findings}


# ── Config knob ──────────────────────────────────────────────────────────────


def test_default_tolerance_is_25_percent():
    assert costs.DEFAULT_TOLERANCE == 0.25


def test_tolerance_is_configurable_via_env_through_config_module():
    sys.path.insert(0, str(ROOT / "source" / "agent"))
    import config as agent_config

    try:
        with mock.patch.dict(os.environ, {"COST_RECONCILIATION_TOLERANCE": "0.5"}):
            importlib.reload(agent_config)
            assert agent_config.COST_RECONCILIATION_TOLERANCE == 0.5
    finally:
        importlib.reload(agent_config)  # restore the default for other tests
    assert agent_config.COST_RECONCILIATION_TOLERANCE == 0.25

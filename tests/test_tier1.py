"""Tests for the web Lambda's Tier 1 deterministic review module.

Everything Tier 1 asserts must be grounded: services carry the text evidence
that matched them, delivery checks are pure word-list/regex, and lens
selection is a static mapping to official AWS lens documents.
"""

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# tier1.py imports `pocvalidator.core` — the name the CDK Lambda bundler gives
# the agent's core/ package at deploy time (see
# infrastructure/cdk/lib/web-stack.ts). Alias it here so that same import
# resolves against the real source/agent/core/ package for local tests.
_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(ROOT / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)

sys.path.insert(0, str(ROOT / "source" / "api"))

import tier1  # noqa: E402

SOW_TEXT = (
    "The platform deploys AWS Lambda functions behind Amazon API Gateway, "
    "stores documents in Amazon S3 and uses Amazon Bedrock for inference. "
    "Amazon CloudWatch provides monitoring. Total cost: $2,400/mo across "
    "an 8-week delivery: Week 1 foundations through Week 8 handover."
)


class TestGroundedDetection:
    def test_detects_only_services_present_in_text(self):
        services, grounding = tier1.detect_services(SOW_TEXT)
        assert {"lambda", "apigateway", "s3", "bedrock", "cloudwatch"} <= set(services)
        assert "aurora" not in services
        for sid in services:
            assert grounding[sid]["grounded"] is True
            assert grounding[sid]["matched"] in SOW_TEXT.lower()
            assert grounding[sid]["evidence"]

    def test_ground_extraction_flags_hallucinated_services(self):
        extraction = {"services": ["s3", "elasticache"], "edges": [], "unmatched": [], "notes": ""}
        out = tier1.ground_extraction(extraction, SOW_TEXT)
        assert out["grounding"]["s3"]["grounded"] is True
        assert out["grounding"]["elasticache"]["grounded"] is False
        assert "elasticache" in out["notes"]


class TestDeliveryChecks:
    BANNED = ["globex ai", "globex", "initech"]

    def test_contamination_cost_and_timeline(self):
        text = "Proposal for Globex AI. Total: $1,500/mo over a 4-week delivery."
        rules = {f["rule_id"]: f for f in tier1.delivery_checks(text, self.BANNED)}
        assert rules["DLV-BRAND"]["severity"] == "Critical"
        assert "globex" in rules["DLV-BRAND"]["title"].lower()
        assert rules["DLV-COST"]["severity"] == "High"
        assert rules["DLV-TIME"]["severity"] == "High"

    def test_current_client_is_not_contamination(self):
        text = "Proposal for Globex AI. Total: $2,400/mo over an 8-week delivery."
        findings = tier1.delivery_checks(text, self.BANNED, client_name="Globex AI")
        assert not any(f["rule_id"] == "DLV-BRAND" for f in findings)

    def test_clean_sow_over_thresholds_passes(self):
        findings = tier1.delivery_checks(SOW_TEXT, self.BANNED)
        assert not any(f["severity"] in ("Critical", "High") for f in findings)

    def test_cost_recovered_from_annual_figure(self):
        text = "TOTAL Annual: $24,047.40 $2,003.95 over 8 weeks of delivery"
        findings = tier1.delivery_checks(text, self.BANNED)
        assert not any(f["rule_id"] == "DLV-COST" for f in findings)

    def test_annual_below_minimum_still_fails(self):
        text = "TOTAL Annual: $12,000.00 over 8 weeks of delivery"
        rules = {f["rule_id"]: f for f in tier1.delivery_checks(text, self.BANNED)}
        assert rules["DLV-COST"]["severity"] == "High"


class TestLensSelection:
    def test_framework_always_first(self):
        lenses = tier1.select_lenses("generic", [], "")
        assert lenses[0]["name"] == "AWS Well-Architected Framework"

    def test_industry_and_services_map_to_official_lenses(self):
        names = {l["name"] for l in tier1.select_lenses("fsi", ["lambda", "bedrock", "kinesis"], "iot core devices")}
        assert "Serverless Applications Lens" in names
        assert "Generative AI Lens" in names
        assert "Data Analytics Lens" in names
        assert "IoT Lens" in names
        assert "Financial Services Industry Lens" in names

    def test_every_lens_links_to_official_docs(self):
        for lens in tier1.select_lenses("fsi", ["lambda", "bedrock", "kinesis", "sagemaker"], "iot saas"):
            assert lens["url"].startswith("https://docs.aws.amazon.com/wellarchitected/")


class TestAttributeOverrides:
    def test_backup_evidence_reaches_the_rule_pack(self):
        text = ("Amazon RDS for PostgreSQL with automated backups enabled "
                "(7-day retention, point-in-time recovery). Total $2,400/mo, 8 weeks.")
        overrides, applied = tier1.attribute_overrides(text, ["rds_postgres"])
        assert overrides["rds_postgres"]["backup_enabled"] is True
        assert any(a["attribute"] == "backup_enabled" for a in applied)

    def test_no_evidence_changes_nothing(self):
        overrides, applied = tier1.attribute_overrides(
            "Amazon RDS for PostgreSQL and Amazon S3.", ["rds_postgres", "s3"])
        assert "backup_enabled" not in overrides.get("rds_postgres", {})

    def test_override_only_lands_on_services_carrying_the_attribute(self):
        text = "MFA enforced on Amazon Cognito. Amazon S3 for storage."
        overrides, _ = tier1.attribute_overrides(text, ["cognito", "s3"])
        assert overrides.get("cognito", {}).get("mfa_enabled") is True
        assert "mfa_enabled" not in overrides.get("s3", {})

    def test_full_run_clears_findings_with_evidence(self):
        text = ("Amazon RDS for PostgreSQL with automated backups enabled "
                "(7-day retention). Access logging enabled on Amazon API Gateway. "
                "Total $2,400/mo over an 8-week delivery.")
        result = tier1.run({"sow_text": text, "segment": "smb", "industry": "generic",
                            "services": [], "edges": []}, banned_brands=[])
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "SMB-002" not in rule_ids          # backups credited
        assert result["evidence_applied"]


class TestWhatIfDeterministic:
    LINES = [
        {"node_id": "ec2", "node_name": "Amazon EC2", "monthly_cost": 100.0},
        {"node_id": "ec2", "node_name": "Amazon EC2", "monthly_cost": 20.0},
        {"node_id": "s3", "node_name": "Amazon S3", "monthly_cost": 30.0},
    ]

    def test_remove_service(self):
        out = tier1.what_if_deterministic("what if we remove S3?", self.LINES)
        assert "$120.00/mo" in out and "-30.00" in out

    def test_double_service(self):
        out = tier1.what_if_deterministic("cost if EC2 doubles?", self.LINES)
        assert "$270.00/mo" in out

    def test_from_to_scaling(self):
        out = tier1.what_if_deterministic(
            "what if ec2 goes from 2 to 4 instances, cost?", self.LINES)
        assert "$270.00/mo" in out

    def test_judgement_questions_return_none(self):
        assert tier1.what_if_deterministic(
            "should we use Graviton for EC2?", self.LINES) is None
        assert tier1.what_if_deterministic(
            "remove the mainframe", self.LINES) is None


class TestFullRun:
    def test_run_produces_agent_shaped_response(self):
        result = tier1.run(
            {"sow_text": SOW_TEXT, "segment": "smb", "industry": "generic",
             "region": "us-east-1", "services": [], "edges": []},
            banned_brands=["initech"],
        )
        assert result["status"] == "complete"
        assert result["tier"] == "deterministic"
        assert result["model_assisted"] is False
        assert result["verdict"]["result"]
        assert isinstance(result["findings"], list)
        assert result["cost"]["total"] > 0
        assert result["sow"]["model_assisted"] is False
        assert result["extraction"]["services"]
        assert all(g["grounded"] for g in result["extraction"]["grounding"].values())
        assert result["lenses"][0]["name"] == "AWS Well-Architected Framework"

    def test_delivery_findings_merge_into_counts(self):
        dirty = SOW_TEXT + " Also references Initech throughout."
        result = tier1.run(
            {"sow_text": dirty, "segment": "smb", "industry": "generic",
             "services": [], "edges": []},
            banned_brands=["initech"],
        )
        assert any(f["rule_id"] == "DLV-BRAND" for f in result["findings"])
        assert result["counts"].get("Critical", 0) >= 1

"""Unit tests for the web Lambda's response parsing and input validation.

Covers the two failure modes found during the 2026-08-23 E2E run against real
SOW documents:
  1. `_reassemble_sse` crashed (`TypeError: expected str instance, dict found`)
     whenever the runtime streamed a JSON *object* event — which is exactly how
     it reports a mid-stream error — turning every agent error into a blind 502.
  2. Unknown segment/industry values sailed through to the runtime's rule-pack
     lookup and died there as `KeyError: 'general'` mid-stream.
"""

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

HANDLER_PATH = Path(__file__).resolve().parents[1] / "source" / "api" / "handler.py"

# handler.py imports tier1, which imports `pocvalidator.core` — the name the
# CDK Lambda bundler gives the agent's core/ package at deploy time (see
# infrastructure/cdk/lib/web-stack.ts). Alias it here so that same import
# resolves against the real source/agent/core/ package for local tests
# (mirrors what /var/task looks like once bundled).
_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(HANDLER_PATH.parents[2] / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)
sys.path.insert(0, str(HANDLER_PATH.parent))


@pytest.fixture(scope="module")
def handler_module(monkeypatch_module=None):
    """Import source/api/handler.py with its required env + a stubbed boto3."""
    import unittest.mock as mock

    env = {
        "AGENT_RUNTIME_ARN": "arn:aws:bedrock-agentcore:us-east-1:0:runtime/x",
        "DEMO_KEY": "test-key",
        "RESULTS_BUCKET": "bucket",
        "PUBLIC_BASE_URL": "https://example.test",
        "VIEWS_TABLE": "table",
        "USER_POOL_ID": "us-east-1_TestPool",
        "USER_POOL_CLIENT_ID": "test-client-id",
        "USERS_TABLE": "users-table",
        "FREE_RUNS": "1",
        "SELF_HOST_URL": "https://github.com/example/self-host",
    }
    with mock.patch.dict("os.environ", env), mock.patch.dict(
        sys.modules, {"boto3": mock.MagicMock(), "botocore.exceptions": types.SimpleNamespace(ClientError=Exception)}
    ):
        spec = importlib.util.spec_from_file_location("web_handler", HANDLER_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod


def _sse(*chunks):
    return "\n".join(f"data: {json.dumps(c)}" for c in chunks) + "\n"


class TestReassembleSse:
    def test_string_chunks_concatenate(self, handler_module):
        raw = _sse("Phase 1\n", "text ", '{"status": "complete"}')
        assert handler_module._reassemble_sse(raw) == 'Phase 1\ntext {"status": "complete"}'

    def test_dict_error_event_does_not_crash(self, handler_module):
        # Regression: the runtime's mid-stream error event is a JSON object.
        raw = _sse("## Phases 2, 3 & 5\n", {"error": "'general'", "error_type": "KeyError"})
        out = handler_module._reassemble_sse(raw)
        assert "'general'" in out  # re-serialised, not dropped, not crashed

    def test_non_sse_text_passes_through(self, handler_module):
        assert handler_module._reassemble_sse('{"status": "complete"}') == '{"status": "complete"}'


class TestExtractTrailingJson:
    def test_trailing_object_after_progress_text(self, handler_module):
        raw = _sse("progress...\n", json.dumps({"status": "complete", "verdict": "ok"}))
        assert handler_module._extract_trailing_json(raw) == {"status": "complete", "verdict": "ok"}

    def test_runtime_error_event_is_recoverable(self, handler_module):
        raw = _sse("progress\n", {"error": "'general'", "error_type": "KeyError", "message": "streaming"})
        parsed = handler_module._extract_trailing_json(raw)
        assert parsed["error"] == "'general'"

    def test_no_json_returns_none(self, handler_module):
        assert handler_module._extract_trailing_json(_sse("just text, no json")) is None


# A verified user's decoded ID-token claims — _handle_invoke no longer reads
# the Authorization header itself (that's _authenticate's job, exercised in
# tests/test_auth_quota.py); it's handed claims directly, matching how the
# routing layer (handler()) calls it after a successful _authenticate().
FAKE_CLAIMS = {
    "sub": "test-sub-aaaa-bbbb-cccc-dddddddddddd",
    "email": "user@example.test",
    "email_verified": True,
    "token_use": "id",
}


class TestInvokeValidation:
    def _event(self, body):
        return {"headers": {"x-demo-key": "test-key"}, "body": json.dumps(body)}

    def test_unknown_industry_rejected_400(self, handler_module):
        resp = handler_module._handle_invoke(
            self._event({"sow_text": "EC2 and S3", "segment": "smb", "industry": "general"}), FAKE_CLAIMS
        )
        assert resp["statusCode"] == 400
        assert "industry" in json.loads(resp["body"])["message"]

    def test_unknown_segment_rejected_400(self, handler_module):
        resp = handler_module._handle_invoke(
            self._event({"sow_text": "EC2 and S3", "segment": "startup", "industry": "generic"}), FAKE_CLAIMS
        )
        assert resp["statusCode"] == 400
        assert "segment" in json.loads(resp["body"])["message"]

    def test_allowed_values_match_page_dropdowns(self, handler_module):
        page = (HANDLER_PATH.parents[1] / "web" / "index.html").read_text()
        for seg in handler_module.ALLOWED_SEGMENTS:
            assert f'value="{seg}"' in page
        for ind in handler_module.ALLOWED_INDUSTRIES:
            assert f'value="{ind}"' in page

    def test_unknown_mode_rejected_400(self, handler_module):
        resp = handler_module._handle_invoke(
            self._event({"sow_text": "EC2 and S3", "segment": "smb",
                         "industry": "generic", "mode": "turbo"}), FAKE_CLAIMS
        )
        assert resp["statusCode"] == 400
        assert "mode" in json.loads(resp["body"])["message"]

    def test_deterministic_mode_completes_without_agent(self, handler_module):
        import unittest.mock as mock

        with mock.patch.object(handler_module, "_client") as client:
            resp = handler_module._handle_invoke(
                self._event({
                    "sow_text": "AWS Lambda behind Amazon API Gateway with Amazon S3. "
                                "Total $2,400/mo over an 8-week delivery.",
                    "segment": "smb", "industry": "generic", "mode": "deterministic",
                }), FAKE_CLAIMS
            )
            client.invoke_agent_runtime.assert_not_called()
        assert resp["statusCode"] == 200
        data = json.loads(resp["body"])
        assert data["status"] == "complete"
        assert data["tier"] == "deterministic"
        assert data["model_assisted"] is False
        assert {"lambda", "apigateway", "s3"} <= set(data["extraction"]["services"])

    def test_deterministic_mode_does_not_touch_quota(self, handler_module):
        """Regression: mode="deterministic" must never call the quota table's
        update_item — only the agent path is metered."""
        import unittest.mock as mock

        with mock.patch.object(handler_module, "_client"), mock.patch.object(
            handler_module, "_users_table"
        ) as users_table:
            resp = handler_module._handle_invoke(
                self._event({
                    "sow_text": "AWS Lambda behind Amazon API Gateway with Amazon S3.",
                    "segment": "smb", "industry": "generic", "mode": "deterministic",
                }), FAKE_CLAIMS
            )
            users_table.update_item.assert_not_called()
        assert resp["statusCode"] == 200

    def test_oversized_document_rejected_413(self, handler_module):
        resp = handler_module._handle_invoke(
            self._event({
                "sow_text": "x" * (handler_module.MAX_DOCUMENT_BYTES + 1),
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }), FAKE_CLAIMS
        )
        assert resp["statusCode"] == 413
        data = json.loads(resp["body"])
        assert data["error"] == "file_too_large"
        assert data["limit_bytes"] == handler_module.MAX_DOCUMENT_BYTES

    def test_agent_mode_without_runtime_arn_returns_503(self, handler_module):
        import unittest.mock as mock

        with mock.patch.object(handler_module, "RUNTIME_ARN", ""):
            resp = handler_module._handle_invoke(
                self._event({"sow_text": "EC2 and S3", "segment": "smb", "industry": "generic"}), FAKE_CLAIMS
            )
        assert resp["statusCode"] == 503
        assert json.loads(resp["body"])["code"] == "agent_not_configured"

    def test_agent_payload_carries_evidence_overrides(self, handler_module):
        import unittest.mock as mock

        stream = mock.MagicMock()
        stream.read.return_value = b'data: "{\\"status\\": \\"complete\\", \\"verdict\\": {}}"'
        with mock.patch.object(handler_module, "_client") as client:
            client.invoke_agent_runtime.return_value = {"response": stream}
            handler_module._handle_invoke(self._event({
                "sow_text": "Amazon RDS for PostgreSQL with automated backups enabled (7-day retention).",
                "segment": "smb", "industry": "generic",
                "services": ["rds_postgres"], "extraction_confirmed": True,
            }), FAKE_CLAIMS)
            sent = json.loads(client.invoke_agent_runtime.call_args.kwargs["payload"])
        assert sent["config_overrides"]["rds_postgres"]["backup_enabled"] is True

    def test_failed_model_extraction_falls_back_to_deterministic(self, handler_module):
        import unittest.mock as mock

        stream = mock.MagicMock()
        stream.read.return_value = (
            b'data: "{\\"status\\": \\"error\\", \\"message\\": '
            b'\\"No services supplied and none extracted.\\"}"')
        with mock.patch.object(handler_module, "_client") as client:
            client.invoke_agent_runtime.return_value = {"response": stream}
            resp = handler_module._handle_invoke(self._event({
                "sow_text": "AWS Lambda with Amazon S3 and Amazon API Gateway. $2,400/mo, 8 weeks.",
                "segment": "smb", "industry": "generic",
            }), FAKE_CLAIMS)
        data = json.loads(resp["body"])
        assert data["status"] == "awaiting_confirmation"
        assert {"lambda", "s3", "apigateway"} <= set(data["extraction"]["services"])
        assert "deterministic text search" in data["extraction"]["notes"]

    def test_runtime_error_event_becomes_clean_502(self, handler_module):
        import unittest.mock as mock

        stream = mock.MagicMock()
        stream.read.return_value = _sse(
            "## Phases 2, 3 & 5\n",
            {"error": "'boom'", "error_type": "KeyError", "message": "An error occurred during streaming"},
        ).encode()
        with mock.patch.object(handler_module, "_client") as client:
            client.invoke_agent_runtime.return_value = {"response": stream}
            resp = handler_module._handle_invoke(
                self._event({"sow_text": "EC2 and S3", "segment": "smb", "industry": "generic"}), FAKE_CLAIMS
            )
        assert resp["statusCode"] == 502
        assert "'boom'" in json.loads(resp["body"])["message"]

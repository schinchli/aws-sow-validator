"""Tests for the AWS-native Gmail poller — the pure logic, no Gmail needed."""

import importlib.util
import io
import json
import sys
import types
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAMBDA_DIR = ROOT / "source" / "api"

# gmail_poller.py imports tier1, which imports `pocvalidator.core` — the name
# the CDK Lambda bundler gives the agent's core/ package at deploy time (see
# infrastructure/cdk/lib/web-stack.ts). Alias it here so that same import
# resolves against the real source/agent/core/ package for local tests.
_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(ROOT / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)

sys.path.insert(0, str(LAMBDA_DIR))


@pytest.fixture(scope="module")
def poller():
    import unittest.mock as mock

    env = {
        "GMAIL_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:0:secret:test",
        "OWNER_EMAIL": "me@example.com",
        "ALIAS_EMAIL": "me+sow@example.com",
        "CONFIG_BUCKET": "site-bucket",
        "AGENT_RUNTIME_ARN": "arn:aws:bedrock-agentcore:us-east-1:0:runtime/x",
        "FROM_ADDRESS": "unused@example.com",  # email_review import needs these
    }
    with mock.patch.dict("os.environ", env), mock.patch.dict(
        sys.modules, {"boto3": mock.MagicMock()}
    ):
        spec = importlib.util.spec_from_file_location(
            "gmail_poller", LAMBDA_DIR / "gmail_poller.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod


class TestChatRouting:
    def test_pricing_words_route_to_what_if(self, poller):
        assert poller.classify_question("what if we swap EC2 for Fargate, cost impact?") \
            == "what_if_question"
        assert poller.classify_question("can we make this cheaper?") == "what_if_question"

    def test_other_questions_route_to_faq(self, poller):
        assert poller.classify_question("why does the verdict say not ready?") == "faq_query"

    def test_strip_quoted_keeps_only_new_text(self, poller):
        text = "Can we drop ElastiCache?\n\nOn Mon, Aug 24, 2026 someone wrote:\n> old stuff"
        assert poller.strip_quoted(text) == "Can we drop ElastiCache?"

    def test_strip_quoted_handles_angle_quotes(self, poller):
        assert poller.strip_quoted("New question\n> quoted line\n> more") == "New question"


class TestSubjectOptions:
    def test_defaults(self, poller):
        assert poller._options_from_subject("SOW review") == ("smb", "generic")

    def test_overrides(self, poller):
        assert poller._options_from_subject("SOW review enterprise fsi") == ("enterprise", "fsi")


class TestReview:
    def test_review_report_produces_text_and_context(self, poller):
        import unittest.mock as mock
        with mock.patch.object(poller, "_banned_brands", return_value=[]):
            result, report = poller.review_report(
                "AWS Lambda behind Amazon API Gateway with Amazon S3. "
                "Total $2,400/mo over an 8-week delivery.", "SOW review")
        assert "SOW REVIEW" in report and "Verdict:" in report
        assert {"lambda", "apigateway", "s3"} <= set(result["extraction"]["services"])


def _docx_b64(text):
    import base64
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml",
                    f"<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>")
    return base64.urlsafe_b64encode(buf.getvalue()).decode()


class TestFullCycle:
    """Simulates one ping end-to-end with a fully scripted Gmail API."""

    def test_ping_processes_new_sow_and_returns_summary(self, poller):
        import unittest.mock as mock

        sow_msg = {
            "id": "m1", "threadId": "t1",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Me <me@example.com>"},
                    {"name": "Subject", "value": "SOW review"},
                    {"name": "Message-ID", "value": "<abc@mail>"},
                ],
                "parts": [{
                    "filename": "sow.docx",
                    "body": {"attachmentId": "a1", "size": 2048},
                }],
            },
        }

        sent, labelled = [], []

        def fake_http(url, data=None, token=None, method=None):
            if "/messages?q=" in url:
                return {"messages": [{"id": "m1"}]}
            if url.endswith("/messages/m1?format=full"):
                return sow_msg
            if "/attachments/a1" in url:
                return {"data": _docx_b64(
                    "AWS Lambda behind Amazon API Gateway with Amazon S3. "
                    "Total $2,400/mo over an 8-week delivery.")}
            if url.endswith("/labels"):
                return {"labels": [{"id": "L1", "name": "sow-processed"}]}
            if url.endswith("/messages/send"):
                sent.append(json.loads(data))
                return {"id": f"sent{len(sent)}"}
            if "/modify" in url:
                labelled.append(url.split("/messages/")[1].split("/")[0])
                return {}
            raise AssertionError(f"unexpected call: {url}")

        with mock.patch.object(poller, "_http", side_effect=fake_http), \
             mock.patch.object(poller, "_access_token", return_value="tok"), \
             mock.patch.object(poller, "_banned_brands", return_value=[]), \
             mock.patch.object(poller, "_save_ctx") as save_ctx:
            resp = poller.handler({"requestContext": {"http": {"method": "GET"}}}, None)

        assert resp["statusCode"] == 200
        assert "Processed 1 SOW review(s)" in resp["body"]
        assert len(sent) == 2                      # ack + report
        import base64
        ack = base64.urlsafe_b64decode(sent[0]["raw"]).decode("utf-8", "ignore")
        report = base64.urlsafe_b64decode(sent[1]["raw"]).decode("utf-8", "ignore")
        assert "running the review now" in ack
        assert "SOW REVIEW" in report and "Verdict:" in report
        assert sent[0]["threadId"] == "t1" and sent[1]["threadId"] == "t1"
        # Original claimed BEFORE any reply; both replies labelled after send.
        assert labelled[0] == "m1"
        assert set(labelled) == {"m1", "sent1", "sent2"}
        save_ctx.assert_called_once()
        assert "lambda" in save_ctx.call_args[0][1]["services"]


class TestAnswerQuestion:
    CTX = {"segment": "smb", "industry": "generic",
           "services": ["ec2", "s3"], "edges": []}

    def _answer(self, poller, agent_result, question="what does this cost?"):
        import unittest.mock as mock
        with mock.patch.object(poller, "_invoke_agent", return_value=agent_result):
            return poller.answer_question(question, self.CTX)

    def test_what_if_stdout_is_rendered_without_code(self, poller):
        out = self._answer(poller, {"status": "complete", "what_if": {
            "status": "ok", "stdout": '"Total drops to $900/mo."',
            "code": "def compute(): ...", "stderr": ""}})
        assert "WHAT-IF PRICING" in out and "$900/mo" in out
        assert "def compute" not in out

    def test_what_if_sandbox_error_never_leaks_traceback(self, poller):
        out = self._answer(poller, {"status": "complete", "what_if": {
            "status": "ok", "stdout": "", "code": "x",
            "stderr": "NameError: name 'json' is not defined"}})
        assert "Could not compute" in out
        assert "NameError" not in out

    def test_faq_text_results_render(self, poller):
        out = self._answer(poller, {"status": "complete", "faq": {
            "status": "ok",
            "results": [{"text": "SMB-002 requires automated backups.", "score": 0.9},
                        {"text": "  ", "score": 0.1}]}},
            question="why backups?")
        assert "FAQ MATCHES" in out
        assert "SMB-002 requires automated backups." in out

    def test_unavailable_features_degrade_to_verdict(self, poller):
        out = self._answer(poller, {
            "status": "complete",
            "verdict": {"result": "Not ready", "reasoning": "1 critical finding"},
            "what_if": {"status": "unavailable", "reason": "Marketplace restriction"},
        })
        assert "unavailable" in out and "Not ready" in out

    def test_no_agent_response_is_graceful(self, poller):
        assert "did not return" in self._answer(poller, None)

    def test_arithmetic_questions_answered_without_the_agent(self, poller):
        import unittest.mock as mock
        ctx = {**self.CTX, "cost_lines": [
            {"node_id": "ec2", "node_name": "Amazon EC2", "monthly_cost": 100.0},
            {"node_id": "s3", "node_name": "Amazon S3", "monthly_cost": 30.0}]}
        with mock.patch.object(poller, "_invoke_agent") as agent:
            out = poller.answer_question("what if we remove S3, cost impact?", ctx)
            agent.assert_not_called()
        assert "deterministic" in out and "$100.00/mo" in out

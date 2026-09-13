"""Tests for the email-in / email-out review Lambda.

The security-relevant behaviours are the ones worth locking down: allowlist
enforcement (silent drop, no bounce), SES verdict handling, and attachment
extraction limits.
"""

import importlib.util
import io
import json
import sys
import types
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAMBDA_DIR = ROOT / "source" / "api"

# email_review.py imports tier1, which imports `pocvalidator.core` — the name
# the CDK Lambda bundler gives the agent's core/ package at deploy time (see
# infrastructure/cdk/lib/web-stack.ts). Alias it here so that same import
# resolves against the real source/agent/core/ package for local tests.
_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(ROOT / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)

sys.path.insert(0, str(LAMBDA_DIR))


@pytest.fixture(scope="module")
def email_module():
    import unittest.mock as mock

    env = {
        "FROM_ADDRESS": "sow@review.example.com",
        "CONFIG_BUCKET": "site-bucket",
        "ALLOWED_SENDERS": "me@example.com, other@example.com",
    }
    with mock.patch.dict("os.environ", env), mock.patch.dict(
        sys.modules, {"boto3": mock.MagicMock()}
    ):
        spec = importlib.util.spec_from_file_location(
            "email_review", LAMBDA_DIR / "email_review.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod


def _docx_bytes(text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "word/document.xml",
            f"<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )
    return buf.getvalue()


def _mime(sender="me@example.com", filename="sow.docx", payload=None, subject="Review please"):
    msg = EmailMessage()
    msg["From"] = f"Someone <{sender}>"
    msg["To"] = "sow@review.example.com"
    msg["Subject"] = subject
    msg.set_content("please review")
    if filename:
        msg.add_attachment(
            payload if payload is not None else _docx_bytes("AWS Lambda with Amazon S3"),
            maintype="application",
            subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename,
        )
    return msg


class TestExtraction:
    def test_docx_attachment_extracts_text(self, email_module):
        import email as email_lib
        import email.policy
        msg = email_lib.message_from_bytes(_mime().as_bytes(), policy=email.policy.default)
        filename, text = email_module.extract_sow(msg)
        assert filename == "sow.docx"
        assert "AWS Lambda with Amazon S3" in text

    def test_no_attachment_returns_none(self, email_module):
        import email as email_lib
        import email.policy
        msg = email_lib.message_from_bytes(
            _mime(filename="").as_bytes(), policy=email.policy.default)
        assert email_module.extract_sow(msg) == (None, None)


class TestSecurity:
    def _invoke(self, email_module, raw_bytes):
        import unittest.mock as mock
        sent = []
        with mock.patch.object(email_module, "_s3") as s3, \
             mock.patch.object(email_module, "_ses") as ses_client, \
             mock.patch.object(email_module, "_banned_brands", return_value=[]):
            s3.get_object.return_value = {"Body": io.BytesIO(raw_bytes)}
            ses_client.send_email.side_effect = lambda **kw: sent.append(kw) or {}
            event = {"Records": [{"s3": {"bucket": {"name": "mail"},
                                          "object": {"key": "inbox/x"}}}]}
            email_module.handler(event, None)
        return sent

    def test_allowlisted_sender_gets_reply(self, email_module):
        sent = self._invoke(email_module, _mime().as_bytes())
        assert len(sent) == 1
        assert sent[0]["Destination"]["ToAddresses"] == ["me@example.com"]
        body = sent[0]["Content"]["Simple"]["Body"]["Text"]["Data"]
        assert "SOW REVIEW" in body and "Verdict:" in body

    def test_stranger_is_dropped_silently(self, email_module):
        sent = self._invoke(email_module, _mime(sender="attacker@evil.com").as_bytes())
        assert sent == []

    def test_spam_verdict_fail_is_dropped(self, email_module):
        msg = _mime()
        msg["X-SES-Spam-Verdict"] = "FAIL"
        assert self._invoke(email_module, msg.as_bytes()) == []

    def test_missing_attachment_gets_helpful_reply(self, email_module):
        sent = self._invoke(email_module, _mime(filename="").as_bytes())
        assert len(sent) == 1
        assert "No usable SOW" in sent[0]["Content"]["Simple"]["Body"]["Text"]["Data"]


class TestReportFormat:
    def test_report_is_plain_text_with_all_sections(self, email_module):
        import tier1
        result = tier1.run(
            {"sow_text": "AWS Lambda behind Amazon API Gateway with Amazon S3. "
                         "Total $2,400/mo over an 8-week delivery.",
             "segment": "smb", "industry": "generic", "services": [], "edges": []},
            banned_brands=[],
        )
        body = email_module.format_report(result, "sow.docx")
        for section in ("SOW REVIEW", "Verdict:", "DELIVERY CHECKS",
                        "WELL-ARCHITECTED LENSES", "SOW SCORE", "SERVICES"):
            assert section in body
        assert "<" not in body.split("https://")[0]  # no markup before first URL

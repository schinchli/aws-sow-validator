"""Tests for the whole-document upload pipeline:

  - source/api/docx_extract.py — stdlib-only .docx extraction (body+tables,
    headers/footers, footnotes, core props, embedded images) and its honest
    coverage report.
  - source/api/handler.py's two routes that wire it in: POST /api/upload-url
    (presigned S3 POST) and upload_key on POST /api/invoke (fetch + extract
    + fold `coverage` into the response).

Builds a real .docx in-memory with zipfile — no python-docx, matching the
stdlib-only constraint the module itself is built under.
"""

import base64
import importlib.util
import io
import json
import re
import sys
import types
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "source" / "api"
sys.path.insert(0, str(API_DIR))

import docx_extract  # noqa: E402 — sys.path insert above must precede this

# ---------------------------------------------------------------------------
# A real in-memory .docx: body paragraph + table, header (one good, one
# deliberately corrupt), footer, footnotes (with a separator entry that must
# NOT be counted), docProps/core.xml, and three images — two raster PNGs of
# different sizes plus one vector WMF bigger than both, to prove the vector
# format is excluded from "largest raster image" selection.
# ---------------------------------------------------------------------------

_DOCUMENT_XML = (
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body>"
    "<w:p><w:r><w:t>Intro text</w:t></w:r></w:p>"
    "<w:tbl>"
    "<w:tr><w:tc><w:p><w:r><w:t>Service</w:t></w:r></w:p></w:tc>"
    "<w:tc><w:p><w:r><w:t>$100/month</w:t></w:r></w:p></w:tc></w:tr>"
    "</w:tbl>"
    "</w:body></w:document>"
)

_HEADER1_XML = (
    '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:p><w:r><w:t>Header text</w:t></w:r></w:p></w:hdr>"
)

_FOOTER1_XML = (
    '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:p><w:r><w:t>Footer text</w:t></w:r></w:p></w:ftr>"
)

_FOOTNOTES_XML = (
    '<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:footnote w:id="-1" w:type="separator"><w:p><w:r><w:t/></w:r></w:p></w:footnote>'
    '<w:footnote w:id="1"><w:p><w:r><w:t>A real footnote</w:t></w:r></w:p></w:footnote>'
    "</w:footnotes>"
)

_CORE_XML = (
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
    "<dc:title>Test SOW</dc:title><dc:creator>Author X</dc:creator>"
    "</cp:coreProperties>"
)

_IMAGE_SMALL = b"PNGDATA-SMALL"
_IMAGE_LARGE = b"PNGDATA-LARGE" * 50
_IMAGE_VECTOR = b"WMFDATA" * 1000  # bigger than both PNGs, but a vector metafile


def _build_test_docx():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("_rels/.rels", "<Relationships/>")
        zf.writestr("word/_rels/document.xml.rels", "<Relationships/>")
        zf.writestr("word/styles.xml", "<w:styles/>")
        zf.writestr("word/document.xml", _DOCUMENT_XML)
        zf.writestr("word/header1.xml", _HEADER1_XML)
        # Deliberately malformed (not valid UTF-8) — must land in
        # unread_parts, never silently dropped or a hard crash.
        zf.writestr("word/header2.xml", b"\xff\xfe<w:hdr>broken")
        zf.writestr("word/footer1.xml", _FOOTER1_XML)
        zf.writestr("word/footnotes.xml", _FOOTNOTES_XML)
        zf.writestr("docProps/core.xml", _CORE_XML)
        zf.writestr("word/media/image1.png", _IMAGE_SMALL)
        zf.writestr("word/media/image2.png", _IMAGE_LARGE)
        zf.writestr("word/media/image3.wmf", _IMAGE_VECTOR)
    return buf.getvalue()


class TestDocxExtract:
    def test_table_cells_join_with_pipe(self):
        result = docx_extract.extract_docx(_build_test_docx())
        assert "Service | $100/month" in result["text"]

    def test_header_and_footer_text_captured(self):
        result = docx_extract.extract_docx(_build_test_docx())
        assert "Header text" in result["text"]
        assert "Footer text" in result["text"]

    def test_footnote_text_and_count(self):
        result = docx_extract.extract_docx(_build_test_docx())
        assert "A real footnote" in result["text"]
        # The synthetic separator entry (id -1) must not be counted.
        assert result["coverage"]["counts"]["footnotes"] == 1

    def test_core_props_captured(self):
        result = docx_extract.extract_docx(_build_test_docx())
        assert result["core_props"]["title"] == "Test SOW"
        assert result["core_props"]["creator"] == "Author X"

    def test_largest_raster_image_is_the_diagram_not_the_vector(self):
        result = docx_extract.extract_docx(_build_test_docx())
        assert result["diagram_part"] == "word/media/image2.png"
        assert result["diagram_format"] == "png"
        assert base64.b64decode(result["diagram_base64"]) == _IMAGE_LARGE

    def test_all_three_images_listed(self):
        result = docx_extract.extract_docx(_build_test_docx())
        parts = {img["part"] for img in result["images"]}
        assert parts == {"word/media/image1.png", "word/media/image2.png", "word/media/image3.wmf"}
        assert result["coverage"]["counts"]["images"] == 3

    def test_corrupt_part_lands_in_unread_parts(self):
        result = docx_extract.extract_docx(_build_test_docx())
        unread = {u["part"]: u["reason"] for u in result["coverage"]["unread_parts"]}
        assert "word/header2.xml" in unread
        assert unread["word/header2.xml"]  # non-empty reason

    def test_coverage_pct_is_over_content_parts_only(self):
        result = docx_extract.extract_docx(_build_test_docx())
        coverage = result["coverage"]
        classifications = {p["name"]: p["classification"] for p in coverage["parts"]}
        # Non-content parts must be classified as such and excluded from the
        # coverage denominator entirely (not "read", not "unread" either).
        assert classifications["[Content_Types].xml"] == "skipped-not-content"
        assert classifications["word/styles.xml"] == "skipped-not-content"
        assert classifications["_rels/.rels"] == "skipped-not-content"
        assert classifications["word/_rels/document.xml.rels"] == "skipped-not-content"
        # Content parts: document.xml, header1, header2, footer1, footnotes,
        # core.xml (6 text/xml parts) + 3 images = 9. header2 fails to parse.
        assert coverage["content_parts_total"] == 9
        assert coverage["content_parts_extracted"] == 8
        assert coverage["coverage_pct"] == round(100 * 8 / 9, 1)

    def test_not_a_zip_raises(self):
        with pytest.raises(Exception):
            docx_extract.extract_docx(b"not a docx at all")


# ---------------------------------------------------------------------------
# handler.py wiring: POST /api/upload-url and upload_key on POST /api/invoke.
# Same import/env/boto3-stub pattern as tests/test_web_handler.py.
# ---------------------------------------------------------------------------

HANDLER_PATH = API_DIR / "handler.py"

_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(ROOT / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)

ENV = {
    "AGENT_RUNTIME_ARN": "arn:aws:bedrock-agentcore:us-east-1:0:runtime/x",
    "DEMO_KEY": "test-key",
    "RESULTS_BUCKET": "bucket",
    "PUBLIC_BASE_URL": "https://example.test",
    "VIEWS_TABLE": "table",
    "USER_POOL_ID": "us-east-1_TestPool",
    "USER_POOL_CLIENT_ID": "test-client-id",
    "USERS_TABLE": "users-table",
    "FREE_RUNS": "5",
    "SELF_HOST_URL": "https://github.com/example/self-host",
    "UPLOADS_BUCKET": "uploads-bucket-test",
}


@pytest.fixture(scope="module")
def handler_module():
    import unittest.mock as mock

    with mock.patch.dict("os.environ", ENV), mock.patch.dict(
        sys.modules, {"boto3": mock.MagicMock(), "botocore.exceptions": types.SimpleNamespace(ClientError=Exception)}
    ):
        spec = importlib.util.spec_from_file_location("web_handler_uploads", HANDLER_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod


FAKE_CLAIMS = {
    "sub": "test-sub-uploads-0001",
    "email": "uploads@example.test",
    "email_verified": True,
    "token_use": "id",
}


def _event(body):
    return {"headers": {"x-demo-key": "test-key"}, "body": json.dumps(body)}


class _FakeBody:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class TestUploadUrlEndpoint:
    def test_presign_response_shape(self, handler_module):
        import unittest.mock as mock

        handler_module._s3.generate_presigned_post = mock.Mock(return_value={
            "url": "https://uploads-bucket-test.s3.amazonaws.com/",
            "fields": {"key": "placeholder", "Content-Type": handler_module.DOCX_MIME},
        })
        resp = handler_module._handle_upload_url(FAKE_CLAIMS)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["upload_url"].startswith("https://")
        # Key shape: uploads/{user_sub}/{uuid}.docx — never the filename.
        assert re.fullmatch(r"uploads/test-sub-uploads-0001/[0-9a-f]{32}\.docx", body["key"])
        assert body["expires_in"] <= 600
        assert body["max_bytes"] == handler_module.MAX_DOCUMENT_BYTES
        assert body["content_type"] == handler_module.DOCX_MIME

    def test_not_configured_without_bucket(self, handler_module):
        import unittest.mock as mock

        with mock.patch.object(handler_module, "UPLOADS_BUCKET", ""):
            resp = handler_module._handle_upload_url(FAKE_CLAIMS)
        assert resp["statusCode"] == 501
        assert json.loads(resp["body"])["code"] == "uploads_not_configured"


class TestInvokeWithUploadKey:
    def test_foreign_upload_key_rejected(self, handler_module):
        resp = handler_module._handle_invoke(
            _event({
                "upload_key": "uploads/someone-else/" + "a" * 32 + ".docx",
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }),
            FAKE_CLAIMS,
        )
        assert resp["statusCode"] == 403

    def test_malformed_upload_key_rejected(self, handler_module):
        resp = handler_module._handle_invoke(
            _event({
                "upload_key": "uploads/" + FAKE_CLAIMS["sub"] + "/not-a-uuid.docx",
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }),
            FAKE_CLAIMS,
        )
        assert resp["statusCode"] == 403

    def test_upload_key_extracts_and_reports_coverage(self, handler_module):
        import unittest.mock as mock

        docx_bytes = _build_test_docx()
        handler_module._s3.get_object = mock.Mock(return_value={"Body": _FakeBody(docx_bytes)})
        key = f"uploads/{FAKE_CLAIMS['sub']}/{'a' * 32}.docx"
        resp = handler_module._handle_invoke(
            _event({"upload_key": key, "segment": "smb", "industry": "generic", "mode": "deterministic"}),
            FAKE_CLAIMS,
        )
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert "coverage" in body
        assert body["coverage"]["content_parts_total"] == 9
        assert body["coverage"]["coverage_pct"] > 0

    def test_oversized_upload_rejected_413(self, handler_module):
        import unittest.mock as mock

        big = b"x" * (handler_module.MAX_DOCUMENT_BYTES + 1)
        handler_module._s3.get_object = mock.Mock(return_value={"Body": _FakeBody(big)})
        key = f"uploads/{FAKE_CLAIMS['sub']}/{'b' * 32}.docx"
        resp = handler_module._handle_invoke(
            _event({"upload_key": key, "segment": "smb", "industry": "generic", "mode": "deterministic"}),
            FAKE_CLAIMS,
        )
        assert resp["statusCode"] == 413

    def test_upload_key_without_uploads_bucket_configured_501(self, handler_module):
        import unittest.mock as mock

        with mock.patch.object(handler_module, "UPLOADS_BUCKET", ""):
            resp = handler_module._handle_invoke(
                _event({
                    "upload_key": f"uploads/{FAKE_CLAIMS['sub']}/{'c' * 32}.docx",
                    "segment": "smb", "industry": "generic", "mode": "deterministic",
                }),
                FAKE_CLAIMS,
            )
        assert resp["statusCode"] == 501


class TestCoverageFinding:
    def test_low_coverage_adds_finding(self, handler_module):
        result = {"status": "complete", "findings": []}
        low_coverage = {"coverage_pct": 50.0, "unread_parts": [{"part": "x", "reason": "y"}]}
        handler_module._attach_coverage(result, low_coverage)
        assert result["coverage"] == low_coverage
        assert any(f["rule_id"] == "DLV-COVERAGE" for f in result["findings"])

    def test_high_coverage_no_finding(self, handler_module):
        result = {"status": "complete", "findings": []}
        handler_module._attach_coverage(result, {"coverage_pct": 95.0})
        assert result["findings"] == []

    def test_none_coverage_is_a_noop(self, handler_module):
        result = {"status": "complete"}
        handler_module._attach_coverage(result, None)
        assert "coverage" not in result

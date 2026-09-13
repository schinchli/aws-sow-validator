"""Tests for the public self-service auth + quota layer added to the web
Lambda: Cognito ID token verification (_verify_jwt/_authenticate), the
configurable (MAX_UPLOAD_BYTES, default 5 MB) document cap, the
FREE_RUNS-per-user quota (no purchasable credits — the answer past quota is
"deploy your own copy"), and /api/me.

Mirrors tests/test_web_handler.py's import/env/boto3-stub pattern so this
file can run standalone or alongside it.
"""

import importlib.util
import json
import sys
import time
import types
from pathlib import Path

import pytest

HANDLER_PATH = Path(__file__).resolve().parents[1] / "source" / "api" / "handler.py"

# handler.py imports tier1, which imports `pocvalidator.core` — the name the
# CDK Lambda bundler gives the agent's core/ package at deploy time (see
# infrastructure/cdk/lib/web-stack.ts). Alias it here so that same import
# resolves against the real source/agent/core/ package for local tests.
_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(HANDLER_PATH.parents[2] / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)
sys.path.insert(0, str(HANDLER_PATH.parent))

ENV = {
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


@pytest.fixture(scope="module")
def handler_module():
    """Import source/api/handler.py with its required env + a stubbed boto3
    (same pattern as tests/test_web_handler.py's fixture)."""
    import unittest.mock as mock

    with mock.patch.dict("os.environ", ENV), mock.patch.dict(
        sys.modules, {"boto3": mock.MagicMock(), "botocore.exceptions": types.SimpleNamespace(ClientError=Exception)}
    ):
        spec = importlib.util.spec_from_file_location("web_handler_auth_quota", HANDLER_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod


@pytest.fixture(scope="module")
def rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_token(handler_module, rsa_keypair, **claim_overrides):
    """Build a Cognito-shaped ID token signed with the test keypair."""
    import jwt as pyjwt

    private_key, _ = rsa_keypair
    now = int(time.time())
    claims = {
        "sub": "test-sub-aaaa-bbbb-cccc-dddddddddddd",
        "email": "user@example.test",
        "email_verified": True,
        "token_use": "id",
        "iss": handler_module.COGNITO_ISSUER,
        "aud": handler_module.USER_POOL_CLIENT_ID,
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(claim_overrides)
    return pyjwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-kid"})


def _stub_jwks(handler_module, rsa_keypair, monkeypatch):
    """Point the module's JWKS client at the test keypair's public half
    instead of making a real network call."""
    _, public_key = rsa_keypair
    monkeypatch.setattr(
        handler_module._jwks_client,
        "get_signing_key_from_jwt",
        lambda token: types.SimpleNamespace(key=public_key),
    )


# ---------------------------------------------------------------------------
# _verify_jwt / _authenticate
# ---------------------------------------------------------------------------


class TestVerifyJwt:
    def test_missing_token_rejected(self, handler_module):
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt("")
        assert exc_info.value.code == "missing_token"
        assert exc_info.value.status == 401

    def test_valid_token_accepted(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair)
        claims = handler_module._verify_jwt(token)
        assert claims["sub"] == "test-sub-aaaa-bbbb-cccc-dddddddddddd"
        assert claims["email"] == "user@example.test"

    def test_bad_audience_rejected(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair, aud="some-other-client-id")
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt(token)
        assert exc_info.value.code == "invalid_audience"

    def test_bad_issuer_rejected(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(
            handler_module, rsa_keypair,
            iss="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SomeoneElse",
        )
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt(token)
        assert exc_info.value.code == "invalid_issuer"

    def test_expired_token_rejected(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        now = int(time.time())
        token = _make_token(handler_module, rsa_keypair, iat=now - 7200, exp=now - 3600)
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt(token)
        assert exc_info.value.code == "token_expired"

    def test_unverified_email_rejected(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair, email_verified=False)
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt(token)
        assert exc_info.value.code == "email_not_verified"

    def test_access_token_use_rejected(self, handler_module, rsa_keypair, monkeypatch):
        """An access token (token_use="access") must not pass as an ID token
        even if somehow it carried aud/iss matching our expectations."""
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair, token_use="access")
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt(token)
        assert exc_info.value.code == "invalid_token_use"

    def test_malformed_token_rejected(self, handler_module):
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt("not-a-jwt-at-all")
        assert exc_info.value.code == "invalid_token"


class TestAuthenticate:
    def test_no_authorization_header_returns_401(self, handler_module):
        claims, err = handler_module._authenticate({"headers": {}})
        assert claims is None
        assert err["statusCode"] == 401
        assert json.loads(err["body"])["code"] == "missing_token"

    def test_bearer_token_extracted_case_insensitively(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair)
        claims, err = handler_module._authenticate({"headers": {"Authorization": f"Bearer {token}"}})
        assert err is None
        assert claims["sub"] == "test-sub-aaaa-bbbb-cccc-dddddddddddd"


# ---------------------------------------------------------------------------
# Document cap: configurable via MAX_UPLOAD_BYTES, default 5 MB (5242880)
# ---------------------------------------------------------------------------


class TestDocumentSizeCap:
    def _event(self, body):
        return {"headers": {}, "body": json.dumps(body)}

    def test_default_cap_is_5mb(self, handler_module):
        # No MAX_UPLOAD_BYTES in ENV (see module-level ENV dict above) —
        # confirms the env-var default, not just whatever value is currently
        # wired into the module.
        assert handler_module.MAX_DOCUMENT_BYTES == 5242880

    def test_max_upload_bytes_env_var_overrides_the_default(self):
        """A custom MAX_UPLOAD_BYTES must flow through to MAX_DOCUMENT_BYTES —
        reimports the module standalone (module-scoped handler_module fixture
        above is fixed to the module ENV) so this doesn't disturb other tests."""
        import unittest.mock as mock

        custom_env = dict(ENV, MAX_UPLOAD_BYTES="10485760")
        with mock.patch.dict("os.environ", custom_env), mock.patch.dict(
            sys.modules,
            {"boto3": mock.MagicMock(), "botocore.exceptions": types.SimpleNamespace(ClientError=Exception)},
        ):
            spec = importlib.util.spec_from_file_location("web_handler_custom_cap", HANDLER_PATH)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

        assert mod.MAX_DOCUMENT_BYTES == 10485760

        claims = {"sub": "u1", "email": "a@b.test"}
        resp = mod._handle_invoke(
            self._event({
                "sow_text": "x" * (10485760 + 1),
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }),
            claims,
        )
        assert resp["statusCode"] == 413
        assert json.loads(resp["body"]) == {"error": "file_too_large", "limit_bytes": 10485760}

    def test_oversized_sow_text_rejected_413(self, handler_module):
        claims = {"sub": "u1", "email": "a@b.test"}
        resp = handler_module._handle_invoke(
            self._event({
                "sow_text": "x" * (handler_module.MAX_DOCUMENT_BYTES + 1),
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }),
            claims,
        )
        assert resp["statusCode"] == 413
        body = json.loads(resp["body"])
        assert body == {"error": "file_too_large", "limit_bytes": handler_module.MAX_DOCUMENT_BYTES}

    def test_oversized_diagram_text_also_rejected(self, handler_module):
        claims = {"sub": "u1", "email": "a@b.test"}
        resp = handler_module._handle_invoke(
            self._event({
                "diagram_text": "y" * (handler_module.MAX_DOCUMENT_BYTES + 1),
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }),
            claims,
        )
        assert resp["statusCode"] == 413

    def test_document_under_cap_is_not_rejected_on_size_grounds(self, handler_module):
        claims = {"sub": "u1", "email": "a@b.test"}
        resp = handler_module._handle_invoke(
            self._event({
                "sow_text": "AWS Lambda with Amazon S3.",
                "segment": "smb", "industry": "generic", "mode": "deterministic",
            }),
            claims,
        )
        assert resp["statusCode"] != 413


# ---------------------------------------------------------------------------
# Quota: FREE_RUNS per user, no purchasable credits
# ---------------------------------------------------------------------------


class TestQuota:
    def _event(self, body):
        return {"headers": {}, "body": json.dumps(body)}

    def test_deterministic_mode_never_consumes_quota(self, handler_module):
        import unittest.mock as mock

        claims = {"sub": "u-det", "email": "det@example.test"}
        with mock.patch.object(handler_module, "_users_table") as users_table:
            resp = handler_module._handle_invoke(
                self._event({
                    "sow_text": "AWS Lambda with Amazon S3 and Amazon API Gateway.",
                    "segment": "smb", "industry": "generic", "mode": "deterministic",
                }),
                claims,
            )
            users_table.update_item.assert_not_called()
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["tier"] == "deterministic"

    def test_agent_mode_exhausted_quota_returns_402_with_self_host_url(self, handler_module):
        import unittest.mock as mock

        claims = {"sub": "u-exhausted", "email": "exhausted@example.test"}

        conditional_fail = Exception("conditional check failed")
        conditional_fail.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

        with mock.patch.object(handler_module, "_client") as client, mock.patch.object(
            handler_module, "_users_table"
        ) as users_table:
            users_table.update_item.side_effect = conditional_fail
            users_table.get_item.return_value = {"Item": {"runs_used": handler_module.FREE_RUNS}}
            resp = handler_module._handle_invoke(
                self._event({"sow_text": "EC2 and S3", "segment": "smb", "industry": "generic"}),
                claims,
            )
            client.invoke_agent_runtime.assert_not_called()

        assert resp["statusCode"] == 402
        body = json.loads(resp["body"])
        assert body["error"] == "quota_exhausted"
        assert body["runs_used"] == handler_module.FREE_RUNS
        assert body["free_runs"] == handler_module.FREE_RUNS
        assert body["self_host_url"] == handler_module.SELF_HOST_URL
        assert "credits" not in body  # no purchasable-credits concept

    def test_agent_mode_within_quota_proceeds(self, handler_module):
        import unittest.mock as mock

        claims = {"sub": "u-fresh", "email": "fresh@example.test"}
        stream = mock.MagicMock()
        stream.read.return_value = b'data: "{\\"status\\": \\"complete\\", \\"verdict\\": {}}"'

        with mock.patch.object(handler_module, "_client") as client, mock.patch.object(
            handler_module, "_users_table"
        ) as users_table:
            client.invoke_agent_runtime.return_value = {"response": stream}
            users_table.update_item.return_value = {"Attributes": {"runs_used": 1}}
            resp = handler_module._handle_invoke(
                self._event({"sow_text": "EC2 and S3", "segment": "smb", "industry": "generic"}),
                claims,
            )
            client.invoke_agent_runtime.assert_called_once()
        assert resp["statusCode"] == 200

    def test_agent_mode_without_runtime_configured_returns_503_before_touching_quota(self, handler_module):
        import unittest.mock as mock

        claims = {"sub": "u-no-agent", "email": "noagent@example.test"}
        with mock.patch.object(handler_module, "RUNTIME_ARN", ""), mock.patch.object(
            handler_module, "_users_table"
        ) as users_table:
            resp = handler_module._handle_invoke(
                self._event({"sow_text": "EC2 and S3", "segment": "smb", "industry": "generic"}),
                claims,
            )
            users_table.update_item.assert_not_called()
        assert resp["statusCode"] == 503
        assert json.loads(resp["body"])["code"] == "agent_not_configured"


# ---------------------------------------------------------------------------
# /api/me
# ---------------------------------------------------------------------------


class TestMe:
    def test_shape_for_a_fresh_user(self, handler_module):
        import unittest.mock as mock

        claims = {"sub": "u-new", "email": "new@example.test"}
        with mock.patch.object(handler_module, "_users_table") as users_table:
            users_table.get_item.return_value = {}
            resp = handler_module._handle_me(claims)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body == {"email": "new@example.test", "runs_used": 0, "free_runs": handler_module.FREE_RUNS}

    def test_shape_for_a_user_with_a_run_used(self, handler_module):
        import unittest.mock as mock

        claims = {"sub": "u-used", "email": "used@example.test"}
        with mock.patch.object(handler_module, "_users_table") as users_table:
            users_table.get_item.return_value = {"Item": {"runs_used": 1}}
            resp = handler_module._handle_me(claims)
        body = json.loads(resp["body"])
        assert body["runs_used"] == 1
        assert body["free_runs"] == handler_module.FREE_RUNS
        assert "credits" not in body

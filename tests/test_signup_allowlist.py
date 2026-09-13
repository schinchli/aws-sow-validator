"""Tests for the sign-up email allowlist: the shared matching rule
(source/api/allowlist.py), the Cognito PreSignUp trigger that is the
authoritative enforcement point (source/api/presignup.py), and the web
Lambda's defence-in-depth re-check on every API call (source/api/handler.py
_verify_jwt).

Mirrors tests/test_auth_quota.py's import/env/boto3-stub pattern for
handler.py.
"""

import importlib.util
import sys
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAMBDA_DIR = ROOT / "source" / "api"
HANDLER_PATH = LAMBDA_DIR / "handler.py"
PRESIGNUP_PATH = LAMBDA_DIR / "presignup.py"

# handler.py imports tier1, which imports `pocvalidator.core` — the name the
# CDK Lambda bundler gives the agent's core/ package at deploy time (see
# infrastructure/cdk/lib/web-stack.ts). Alias it here so that same import
# resolves against the real source/agent/core/ package for local tests.
_pocvalidator = types.ModuleType("pocvalidator")
_pocvalidator.__path__ = [str(ROOT / "source" / "agent")]
sys.modules.setdefault("pocvalidator", _pocvalidator)
sys.path.insert(0, str(LAMBDA_DIR))

# schinchli/gmail.com — the personal-address half of this project's own
# default allowlist (see infrastructure/cdk/lib/web-stack.ts DEFAULT_SIGNUP_ALLOWED).
DEFAULT_ALLOWED = "amazon.com,schinchli@gmail.com"


# ---------------------------------------------------------------------------
# allowlist.is_signup_allowed — the shared matching rule
# ---------------------------------------------------------------------------

from allowlist import is_signup_allowed  # noqa: E402 — needs sys.path set up above


class TestIsSignupAllowed:
    def test_amazon_domain_address_allowed(self):
        assert is_signup_allowed("user@amazon.com", DEFAULT_ALLOWED) is True

    def test_exact_personal_address_allowed(self):
        assert is_signup_allowed("schinchli@gmail.com", DEFAULT_ALLOWED) is True

    def test_exact_address_match_is_case_insensitive(self):
        assert is_signup_allowed("SCHINCHLI@GMAIL.COM", DEFAULT_ALLOWED) is True

    def test_domain_match_is_case_insensitive(self):
        assert is_signup_allowed("User@AMAZON.COM", DEFAULT_ALLOWED) is True

    def test_lookalike_domain_rejected(self):
        """A naive `endswith('amazon.com')` would wrongly allow this."""
        assert is_signup_allowed("user@notamazon.com", DEFAULT_ALLOWED) is False

    def test_lookalike_suffix_domain_rejected(self):
        """A naive `endswith('amazon.com')` would wrongly allow this too."""
        assert is_signup_allowed("user@amazon.com.evil.com", DEFAULT_ALLOWED) is False

    def test_subdomain_rejected(self):
        """Domain entries match exactly — a subdomain is not the same domain."""
        assert is_signup_allowed("user@sub.amazon.com", DEFAULT_ALLOWED) is False

    def test_unrelated_address_rejected(self):
        assert is_signup_allowed("someone@example.com", DEFAULT_ALLOWED) is False

    def test_empty_allowlist_allows_everyone(self):
        assert is_signup_allowed("anyone@example.com", "") is True

    def test_whitespace_only_allowlist_allows_everyone(self):
        assert is_signup_allowed("anyone@example.com", "   ") is True

    def test_none_allowlist_allows_everyone(self):
        assert is_signup_allowed("anyone@example.com", None) is True

    def test_whitespace_around_entries_is_stripped(self):
        assert is_signup_allowed("user@amazon.com", "  amazon.com , schinchli@gmail.com ") is True

    def test_whitespace_around_email_is_stripped(self):
        assert is_signup_allowed("  user@amazon.com  ", DEFAULT_ALLOWED) is True

    def test_missing_at_sign_rejected_when_allowlist_configured(self):
        assert is_signup_allowed("not-an-email", DEFAULT_ALLOWED) is False

    def test_empty_email_rejected_when_allowlist_configured(self):
        assert is_signup_allowed("", DEFAULT_ALLOWED) is False

    def test_trailing_at_sign_with_no_domain_rejected(self):
        assert is_signup_allowed("user@", DEFAULT_ALLOWED) is False


# ---------------------------------------------------------------------------
# presignup.handler — the authoritative Cognito PreSignUp trigger
# ---------------------------------------------------------------------------


def _cognito_event(email):
    return {
        "request": {"userAttributes": {"email": email}},
        "response": {},
    }


@pytest.fixture()
def presignup_module(monkeypatch):
    monkeypatch.setenv("SIGNUP_ALLOWED", DEFAULT_ALLOWED)
    monkeypatch.setenv("SELF_HOST_URL", "https://github.com/example/self-host")
    spec = importlib.util.spec_from_file_location("web_presignup", PRESIGNUP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPresignupTrigger:
    def test_allowed_address_passes_through_unmodified(self, presignup_module):
        event = _cognito_event("user@amazon.com")
        result = presignup_module.handler(event, None)
        assert result is event
        # Must NOT auto-confirm or auto-verify — the normal verify-by-code
        # flow must still run for an allowed address.
        assert "autoConfirmUser" not in result["response"]
        assert "autoVerifyEmail" not in result["response"]

    def test_disallowed_address_raises_a_user_facing_error(self, presignup_module):
        with pytest.raises(Exception) as exc_info:
            presignup_module.handler(_cognito_event("user@notamazon.com"), None)
        message = str(exc_info.value)
        assert "fork" in message.lower()
        assert "self-host" in message.lower() or "github.com" in message.lower()

    def test_open_allowlist_allows_any_address(self, monkeypatch):
        monkeypatch.setenv("SIGNUP_ALLOWED", "")
        monkeypatch.setenv("SELF_HOST_URL", "https://github.com/example/self-host")
        spec = importlib.util.spec_from_file_location("web_presignup_open", PRESIGNUP_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        event = _cognito_event("anyone@example.com")
        assert mod.handler(event, None) is event


# ---------------------------------------------------------------------------
# handler.py _verify_jwt — defence-in-depth re-check on every API call
# ---------------------------------------------------------------------------

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
    "SIGNUP_ALLOWED": DEFAULT_ALLOWED,
}


@pytest.fixture(scope="module")
def handler_module():
    import unittest.mock as mock

    with mock.patch.dict("os.environ", ENV), mock.patch.dict(
        sys.modules, {"boto3": mock.MagicMock(), "botocore.exceptions": types.SimpleNamespace(ClientError=Exception)}
    ):
        spec = importlib.util.spec_from_file_location("web_handler_signup_allowlist", HANDLER_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod


@pytest.fixture(scope="module")
def rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_token(handler_module, rsa_keypair, **claim_overrides):
    import jwt as pyjwt

    private_key, _ = rsa_keypair
    now = int(time.time())
    claims = {
        "sub": "test-sub-aaaa-bbbb-cccc-dddddddddddd",
        "email": "user@amazon.com",
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
    _, public_key = rsa_keypair
    monkeypatch.setattr(
        handler_module._jwks_client,
        "get_signing_key_from_jwt",
        lambda token: types.SimpleNamespace(key=public_key),
    )


class TestHandlerDefenceInDepth:
    def test_allowed_email_claim_accepted(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair, email="user@amazon.com")
        claims = handler_module._verify_jwt(token)
        assert claims["email"] == "user@amazon.com"

    def test_disallowed_email_claim_rejected_with_403(self, handler_module, rsa_keypair, monkeypatch):
        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair, email="user@notamazon.com")
        with pytest.raises(handler_module.AuthError) as exc_info:
            handler_module._verify_jwt(token)
        assert exc_info.value.code == "email_not_allowed"
        assert exc_info.value.status == 403

    def test_authenticate_surfaces_403_for_disallowed_email(self, handler_module, rsa_keypair, monkeypatch):
        import json as _json

        _stub_jwks(handler_module, rsa_keypair, monkeypatch)
        token = _make_token(handler_module, rsa_keypair, email="someone@example.com")
        claims, err = handler_module._authenticate({"headers": {"Authorization": f"Bearer {token}"}})
        assert claims is None
        assert err["statusCode"] == 403
        assert _json.loads(err["body"])["code"] == "email_not_allowed"

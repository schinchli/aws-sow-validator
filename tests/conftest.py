"""Shared, session-wide pytest configuration.

Works around a garbage-collection bug observed in this environment's
`cryptography` build: once an RSA private key object created via
`rsa.generate_private_key()` is garbage collected, subsequent RS256 signing
anywhere else in the same process starts failing with
`TypeError: Expected instance of hashes.HashAlgorithm.` (inside
`jwt.algorithms.RSAAlgorithm.sign`). This has nothing to do with the key
that was collected — it corrupts a process-wide OpenSSL/hashing code path
used by every later `jwt.encode(..., algorithm="RS256")` call.

Concretely: tests/test_auth_quota.py's `rsa_keypair` fixture is
module-scoped, so its key is dropped (and GC'd) as soon as that test module
finishes — which then breaks RS256 signing for any *other* test module that
signs its own JWTs afterwards (e.g. tests/test_signup_allowlist.py),
regardless of test order.

The fix: keep every RSA key generated during the test session alive so none
of them are ever collected mid-run. This changes nothing about test
behavior or coverage — it only prevents an unrelated environment bug from
producing order-dependent failures.
"""

_RSA_KEY_KEEPALIVE = []


def pytest_configure(config):  # noqa: ARG001 — required pytest hook signature
    from cryptography.hazmat.primitives.asymmetric import rsa

    if getattr(rsa.generate_private_key, "_signup_allowlist_keepalive", False):
        return  # already wrapped (e.g. re-entrant test runs in-process)

    original_generate_private_key = rsa.generate_private_key

    def _generate_private_key_and_keep_alive(*args, **kwargs):
        key = original_generate_private_key(*args, **kwargs)
        _RSA_KEY_KEEPALIVE.append(key)
        return key

    _generate_private_key_and_keep_alive._signup_allowlist_keepalive = True
    rsa.generate_private_key = _generate_private_key_and_keep_alive

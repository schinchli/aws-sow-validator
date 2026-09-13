"""Cognito PreSignUp trigger for the poc-validator end-user pool.

This is the authoritative enforcement point for the sign-up allowlist: a
browser-side check is trivially bypassed by calling the Cognito
SignUp/AdminCreateUser API directly, so the allowlist MUST be enforced here,
not (only) in the web Lambda — see source/api/handler.py's defence-in-depth
check for the second layer.

Configured entirely via the SIGNUP_ALLOWED env var (see allowlist.py for the
exact matching rule) so a fork can point this at its own allowlist, or unset
it entirely to allow open sign-up, without editing any code.

Deliberately does NOT set autoConfirmUser / autoVerifyEmail on the event:
an allowed address still goes through Cognito's normal
verify-by-code flow untouched. Rejection is a plain raised exception —
Cognito surfaces its message verbatim to the SignUp caller.
"""

import os

from allowlist import is_signup_allowed

SIGNUP_ALLOWED = os.environ.get("SIGNUP_ALLOWED", "")
# Reuses the same "go deploy your own copy" pointer the web Lambda gives
# quota-exhausted users (see source/api/handler.py SELF_HOST_URL) so the
# rejection message and the quota message stay consistent.
SELF_HOST_URL = os.environ.get(
    "SELF_HOST_URL", "https://github.com/awslabs/agentcore-samples")


def handler(event, context):  # noqa: ARG001 — context required by the Lambda trigger contract
    email = ((event.get("request") or {}).get("userAttributes") or {}).get("email", "")
    if not is_signup_allowed(email, SIGNUP_ALLOWED):
        raise Exception(
            "Sign-up for this hosted instance is restricted to an allowlist "
            "of email addresses. To use this tool with your own account, "
            f"fork the repository and deploy your own copy into your own "
            f"AWS account: {SELF_HOST_URL}"
        )
    return event

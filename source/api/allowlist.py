"""Shared email allowlist logic, used by both the Cognito PreSignUp trigger
(source/api/presignup.py — the authoritative enforcement point) and the web
Lambda's JWT verification (source/api/handler.py — defence in depth, in case
a user pool is ever reconfigured to bypass the trigger).

Configuration is a single comma-separated string (the SIGNUP_ALLOWED env
var in both Lambdas), so a fork can change or disable the policy without
touching code:
  - an entry containing "@" is an exact address match (case-insensitive)
  - an entry without "@" is a domain match: the address's domain must equal
    that value *exactly* — no `endswith` substring matching, so a lookalike
    domain (e.g. "amazon.com.evil.com") or a subdomain (e.g.
    "sub.amazon.com") is rejected even though "amazon.com" is allowed
  - an empty/whitespace-only string means "allow everyone" — the sensible
    default for a fork with no allowlist configured
"""


def is_signup_allowed(email: str, allowed_raw: str) -> bool:
    """Return True iff `email` is permitted, per `allowed_raw` (see module
    docstring for the format). Never guesses: an email with no "@" is
    rejected outright once an allowlist is configured."""
    allowed_raw = (allowed_raw or "").strip()
    if not allowed_raw:
        return True

    email = (email or "").strip().lower()
    if "@" not in email:
        return False
    _, _, email_domain = email.rpartition("@")
    if not email_domain:
        return False

    for raw_entry in allowed_raw.split(","):
        entry = raw_entry.strip().lower()
        if not entry:
            continue
        if "@" in entry:
            if email == entry:
                return True
        elif email_domain == entry:
            return True
    return False

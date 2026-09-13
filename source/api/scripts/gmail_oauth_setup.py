#!/usr/bin/env python3
"""One-time Gmail OAuth setup for the poc-validator gmail poller.

Prereq (Google side, ~3 min): console.cloud.google.com → create/select a
project → "APIs & Services" → enable the Gmail API → "Credentials" → Create
OAuth client ID → type "Desktop app". Copy the client id + secret.

Run:  python3 gmail_oauth_setup.py --client-id <id> --client-secret <secret>

It opens the consent URL, catches the redirect on localhost, exchanges the
code for a refresh token, and prints the exact JSON + AWS CLI command to
store it in Secrets Manager. Nothing is written anywhere by this script.
"""

import argparse
import http.server
import json
import threading
import urllib.parse
import urllib.request
import webbrowser

SCOPES = "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send"
PORT = 8765
REDIRECT = f"http://localhost:{PORT}"

captured = {}


class Catcher(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — stdlib API
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        captured["code"] = (query.get("code") or [""])[0]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Done - return to the terminal.")

    def log_message(self, *args):  # silence request logging
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--client-secret", required=True)
    args = ap.parse_args()

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": args.client_id,
        "redirect_uri": REDIRECT,
        "response_type": "code",
        "scope": SCOPES,
        "access_type": "offline",
        "prompt": "consent",
    })
    server = http.server.HTTPServer(("localhost", PORT), Catcher)
    threading.Thread(target=server.handle_request, daemon=True).start()
    print(f"Opening consent page (sign in as the mailbox owner):\n{auth_url}\n")
    webbrowser.open(auth_url)
    while "code" not in captured:
        pass
    server.server_close()

    body = urllib.parse.urlencode({
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "code": captured["code"],
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT,
    }).encode()
    with urllib.request.urlopen(
            urllib.request.Request("https://oauth2.googleapis.com/token", data=body),
            timeout=30) as resp:
        tokens = json.loads(resp.read())

    secret = json.dumps({
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "refresh_token": tokens["refresh_token"],
    })
    print("\nStore this in Secrets Manager:\n")
    print("aws secretsmanager create-secret --region us-east-1 \\")
    print("  --name poc-validator/gmail-oauth \\")
    print(f"  --secret-string '{secret}'")
    print("\nThen deploy with:  --context gmailSecretArn=<the ARN printed above>"
          " --context gmailOwner=<your@gmail.com>")


if __name__ == "__main__":
    main()

# Google Drive integration (optional)

The Gatekeeper page can list and validate `.docx` documents straight from a Google Drive
folder. The feature is **off by default**: until the two values below are provisioned, the
`/api/drive/*` routes return a clean `drive_not_configured` error and the page shows a
"not configured" note. Nothing else in the stack depends on it.

The browser never talks to Google and never sees the service-account key — the Lambda holds
the credential (via Secrets Manager), downloads the file server-side, extracts the text with
the Python standard library, and returns only the text.

## One-time setup (~10 minutes, needs a Google account)

1. **Create a service account**
   - In the [Google Cloud console](https://console.cloud.google.com/), create (or pick) a
     project → **APIs & Services → Enable APIs** → enable **Google Drive API**.
   - **IAM & Admin → Service Accounts → Create service account** (any name, no roles needed).
   - Open the service account → **Keys → Add key → JSON**. A key file downloads.

2. **Share the folder**
   - In Google Drive, share the folder that holds the SOWs with the service account's email
     (`…@…iam.gserviceaccount.com`) as **Viewer**.
   - Note the folder id: it is the last path segment of the folder's URL
     (`https://drive.google.com/drive/folders/<FOLDER_ID>`).

3. **Store the key in AWS Secrets Manager** (same account/region as the web stack):
   ```bash
   aws secretsmanager create-secret \
     --name poc-validator/google-drive-sa \
     --secret-string file:///path/to/downloaded-key.json
   # note the ARN in the output
   ```
   Then delete the local key file.

4. **Redeploy the web stack with the two extra contexts** (alongside the usual four):
   ```bash
   cd infrastructure/cdk && npm run build
   npx cdk deploy \
     --context agentRuntimeArn=... --context demoKey=... \
     --context basicAuthCredentialBase64=... --context publicBaseUrl=... \
     --context driveSaSecretArn="arn:aws:secretsmanager:...:secret:poc-validator/google-drive-sa-XXXX" \
     --context driveFolderId="<FOLDER_ID>"
   ```
   The deploy adds exactly one IAM statement: `secretsmanager:GetSecretValue` on that secret.

5. **Verify**: open the Gatekeeper page → "browse the Google Drive folder" → the folder's
   documents list; "Validate all" batch-checks every one.

## Scope and limits

- Read-only Drive scope (`drive.readonly`); the Lambda additionally refuses any file whose
  parent is not the configured folder.
- `.docx` files and native Google Docs (exported as .docx) only; 30 MB per-file cap.
- To rotate the key: upload a new JSON key to the same secret
  (`aws secretsmanager put-secret-value`) — no redeploy needed (tokens are minted per
  Lambda container, cached ≤ 1 hour).
- To turn the feature off again: redeploy without the two `drive*` contexts.

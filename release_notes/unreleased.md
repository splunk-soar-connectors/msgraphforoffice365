**Unreleased**

* Encoded caller-controlled Microsoft Graph path segments to prevent request-path traversal (PAPP-37963; PSAAS-30639).
* Restricted pagination to the Microsoft Graph origin and bounded page traversal (PAPP-37963; PSAAS-30712, PSAAS-31866).
* Applied JavaScript-context escaping to action-result widget context menus (PAPP-37963; PSAAS-30800, PSAAS-30989, PSAAS-31024, PSAAS-31030, PSAAS-31169).
* Bound OAuth callbacks to their initiating authorization flow with a single-use nonce (PAPP-37963; PSAAS-31186).
* Validated attachment upload origins and bounded throttled upload retries (PAPP-37963; PSAAS-31187, PSAAS-32142).
* Redacted OAuth token responses from action debug data (PAPP-37963; PSAAS-32098).
* Preserved poll checkpoints on ingestion failure and bounded duplicate-only polling cycles (PAPP-37963; PSAAS-32324, PSAAS-32331).
* Limited nested item-attachment extraction depth and surfaced depth failures (PAPP-37963; PSAAS-32418).

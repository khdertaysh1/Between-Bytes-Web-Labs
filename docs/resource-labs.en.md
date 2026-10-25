# Resource and identity labs · 0.12.0

Four independent rooms add 24 cases to the existing manual workspace. Every case has Arabic/English feature context, a control, a modified request, expected evidence and repair guidance. Existing request editing, replay, comparison and encoding tools work throughout.

| Room | Six cases |
|---|---|
| Uploads | Active extension, double extension, declared MIME, filename traversal, cross-user overwrite, active SVG policy |
| Path traversal | Relative, URL encoding, double decoding, alternate separators, absolute paths, directory-prefix confusion |
| Disclosure | Environment file, Git metadata, configuration backup, autoindex, verbose errors, server secret in client configuration |
| Recovery and sessions | Account binding, consumed token, expired token, revoked session, incomplete MFA, token purpose |

Run the fixed control first, modify one boundary-crossing field, send the vulnerable request, then replay the identical input against the fix. Inspect status, body and persisted effect. Select two records in Requests to compare them. Reset starts a new round.

Upload success returns 201; invalid format returns 415; forbidden owner/path returns 403. Inspect files, resolved_path and execution_performed=false. The virtual store is capped at 30 entries; a full store returns 409. Path reads return 403 outside the public root and 404 for a missing file inside it. Fixed client configuration intentionally stays HTTP 200 while omitting the secret field. Reset tokens are consumed after a successful reset; replay must fail. Account revisions make accepted changes observable.

All resources, accounts, credentials and files are in-memory fixtures. No host filesystem, external transport, email, actual upload execution or cryptographic token validation occurs. PNG:/HTML: are explicit content-format fixtures, not production image decoding. SVG acceptance demonstrates a storage policy failure, not proven script execution. Production repairs need trusted parsers, robust isolation and sanitization, safe storage, size/quotas, and canonical filesystem containment that also considers symlinks. Snippets communicate principles, not complete production implementations.

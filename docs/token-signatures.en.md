# Token signature exercise · 0.12.2

Open Code flaws → Decoding a token without verifying its signature. Run the fixed
normal control (200/viewer). Decode the middle base64url segment, change role to
admin and re-encode it without signing again. Send your edited token to vulnerable
and fixed. Compare effective_role, admin_panel and signature_verified: fixed returns
401 without privileges for invalid integrity. Three progressive hints are available.
Completion requires matching impact/rejection and a valid fixed control, not viewing
a comparison. The general Base64 tool needs -/_ translated to +/ and padding restored
for decoding; reverse that conversion and strip padding to encode base64url.

HMAC-SHA256 is actual local computation, but the key is public and the clock is fixed
at 2000000000 for a deterministic classroom. This is not production authentication
or a full JWT library. Fixed checks an algorithm allowlist, integrity and expiry;
issuer/audience, key management and revocation are outside scope. Use a vetted
library with secret keys and a complete validation contract in production.

Primary reference reviewed 2026-11-21: https://www.rfc-editor.org/rfc/rfc8725.html .
Original code/prose under project MIT; no upstream text copied.

Publication review on 2026-11-21 found no README/homepage URL, has_pages=false and a
404 public Pages endpoint. No deployed website was inspected or guessed. Main is
0.12.0/96 cases; HPP PR #3 is still unmerged. This independent main-based proposal
has 97 cases; merging both proposals later needs count 98 and explicit conflict
resolution. Existing PR branches, styles and rooms are preserved.

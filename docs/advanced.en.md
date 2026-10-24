# Six added lessons (0.5)

The course now has 13 lessons across six levels, maximum 1300 points. Levels 4, 5 and 6 unlock after all prior assessments at 700, 900 and 1100 points. Existing 0.4 exam scores remain intact. Practice and automatic demos still award no points.

## Browser-origin exercises

CSRF and CORS use two real HTTP origins on IPv4 loopback: the main app and an automatically allocated second port. Both origins are same-site but cross-origin. A synthetic HttpOnly/SameSite=Lax cookie represents the classroom session. It is not production authentication or a test of cross-site SameSite bypass. Server shutdown closes the second-origin listener.

CSRF: the second origin sends a credentialed simple POST in no-cors mode. The response is opaque; the main app checks note/revision before and after. Vulnerable mode accepts the write; fixed checks both the actual Origin header and a session-bound token. A legitimate fixed write must still succeed. No actual user account, payment or email is involved. The exception to the main app's origin checks is scoped to the synthetic note write endpoint only.

CORS: the second origin performs a credentialed fetch. Vulnerable mode reflects its browser-supplied Origin and allows credentials; its JavaScript can read synthetic private data. Fixed withholds permission from that origin, so the browser blocks reading even though the server may return 200. A same-origin authenticated read remains available. CORS is not server authorization or a substitute for CSRF controls. Tests also check headers and authentication; an arbitrary fetch failure alone is not evidence of a CORS policy.

## Explicitly modeled behavior

Open redirect displays a JSON policy decision (`would_status:302`, location), not an actual 302 response or external navigation. Fixed mode uses explicit local routes; external and protocol-relative destinations are rejected. Practice uses /welcome and an outside.example fixture, assessment uses /account and a different path. No external URL is followed.

SSRF uses a closed synthetic transport: public.lab/welcome, internal.lab/config, and public.lab/redirect. It performs no DNS, sockets, HTTP-client calls or file reads. The model shows private content and redirect following only in vulnerable mode; fixed rejects the internal destination/redirect and allows the public resource. It does not reproduce real DNS rebinding, address parsing or metadata access.

API-key disclosure and exposed-file lessons read a fixed in-memory dictionary, never the host filesystem. JavaScript fixtures contain intentionally invalid DEMO_ONLY server secrets alongside a publishable demo key. Fixed removes the former and preserves the latter. File fixtures include robots.txt, .env.backup, backups/settings.env and .git/config; fixed refuses private files while retaining public resources. Unknown paths and traversal-like inputs do not read anything. No credential validation against real providers exists.

## Developer checks

Python tests cover policy decisions, invalid destinations, synthetic secret/file handling, CSRF session/origin/token enforcement, CORS authentication/headers and unchanged protection of unrelated routes. Optional Playwright checks cover all 13 practical assessments, actual credentialed cross-origin read/write behavior, scoring/prerequisites, reload persistence, XSS isolation and mobile layouts. The browser test asserts requests stay on 127.0.0.1.

References: [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS), [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

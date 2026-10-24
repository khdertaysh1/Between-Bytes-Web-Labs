# Lab guide · 0.10.0

Nine independent labs contain 72 open cases. There are no points or locked levels. Each case explains the feature, the missing check, a short experiment and how to interpret the result. Implementation details live in an expandable repair section.

| Lab | Six cases |
|---|---|
| SSRF | Internal service, loopback, public-to-private redirect, URL userinfo, DNS validation/connection mismatch, administrative port |
| CSRF | Missing verification, empty token, cross-session token, unsafe origin exemption, state-changing GET, content-type gap |
| CORS | Origin reflection, null origin, origin prefix, hostname suffix, ignored scheme, broad preflight and actual response |
| Open Redirect | Absolute URL, protocol-relative URL, backslash normalization, decoding order, misleading host prefix, nested redirect |

Each row is a separate lab card, with six cases in its own navigation. The remaining five labs cover payment (16), XSS (12), access control (10), rate limits (7), and SQL/NoSQL/templates (3).

## First experiment

Open CSRF → “Token not bound to the session.” Run the fixed control: Alice’s token updates her note. Load the case example, which submits Bob’s token instead. The vulnerable policy applies it; the fixed policy returns 403 and preserves the previous note. Inspect `before`, `note` and `operation_applied`. `changed` is false for an idempotent write of the same note even when the operation applied. Reset a round to start again from the original state.

CORS is about response readability, not merely status. Inspect `response_headers`, `readable`, `private` and, when present, `preflight`. A resource can return 200 while CORS denies another origin permission to read it. Rejected preflight prevents the actual browser request; `http_status_of_fixture_get` describes the separate modeled resource.

In SSRF, inspect `trace` and private content. A rejected destination must not reach a fixture-read step. In Open Redirect, inspect the normalized destination and `external`; `navigation_performed` remains false. A 200 response is the decision API, not an HTTP 302 redirect.

## Evidence boundaries

The four request-security labs are closed policy simulations. Origin, credentials, tokens and DNS results are teaching inputs, not genuine browser headers or network behavior. They are not proof of a real CSRF/CORS exploit, DNS rebinding or SameSite bypass. No URLs shown in these cases are fetched. SQL runs against real in-memory SQLite; XSS previews run in an isolated browser frame. Evidence labels distinguish these modes.

## Run and update

Python 3.10+ and Git are sufficient; no extra Python packages are needed. In Termux install `python git` with `pkg install`, then clone the repository and run `python app.py --port 8002`.

For an existing checkout, stop the server with Ctrl+C and run:

```bash
git pull --ff-only origin main
python app.py --port 8002
```

Open http://127.0.0.1:8002/ and verify version 0.10.0 with nine lab cards. The old UI is removed; `/foundations` redirects to the current interface.

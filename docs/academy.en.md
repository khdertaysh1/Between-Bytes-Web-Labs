# Scenario Academy · v0.8

50 advanced cases in addition to the thirteen foundation rooms. Every case is open, without points or unlock requirements. Run `python app.py` and open `http://127.0.0.1:8000/academy`.

## Investigation flow

Load the control input and run it against the fixed variant first. Edit JSON to demonstrate vulnerable impact, then replay exactly the same input against the fix. For rate-limit cases, exhaust the vulnerable starting budget before using the second example. New round resets the current case state; it does not remove a saved completion mark.

Checks bind vulnerable impact to fixed protection using the same request-body fingerprint, and require a functioning fixed control. Server-model flags are learning aids, not tamper-resistant exams. The current page holds exportable evidence; localStorage holds completion marks and conclusions. Switching language clears the current round display but preserves server state.

## Execution boundaries

Payments are entirely synthetic: integer minor units and seeded provider records; no gateway, cards, charges or real refunds. The webhook case uses a public signature-verdict fixture, not a provider protocol or real signature generation. The gift case deterministically models a stale-read interleaving rather than running an actual network race.

IP addresses are documentation-range labels. No device IP changes or proxies are used. The window exercise uses an explicit bounded 0..120 synthetic clock, not a production client-controlled clock. Production account and source limits require threat-model-specific design; this engine focuses on the account budget for the bypass cases.

XSS executes only in an iframe sandbox without allow-same-origin, with CSP blocking network connections and external resources. alert reports a per-preview-token signal to the parent. Execution and absence-of-signal checks are browser-assisted and time-bounded; the server issues no execution-proof flag for XSS cases. Fixed previews may show text or a static link; no automatic external navigation occurs. Stored XSS saves a comment in the server session before a separate GET renders it. DOM cases read actual location.hash and search parameters on the preview URL.

SQLi uses real in-memory SQLite with two synthetic rows. NoSQL, template evaluation, SSRF and redirect cases use closed fixtures illustrating specific decisions: no eval, actual NoSQL service, DNS, external transport or host-file reads. Coverage is not exhaustive for XSS or payments; learning difficulty is not severity.

Sessions are local-browser contexts, capped at 32 and expiring after 30 minutes idle; state is in memory and disappears on restart. This is not container isolation or a production account system. Use 127.0.0.1 only.

## 1. Client-controlled price · `pay-price`

The server trusts a submitted unit price instead of its product catalog.

Fix: Resolve the price from the server catalog; ignore client prices.

Control input:

```json
{
  "price": 10000
}
```

Investigation example after understanding the cause:

```json
{
  "price": 1
}
```

## 2. Negative quantities · `pay-quantity`

A negative quantity turns a charge into synthetic credit.

Fix: Require an integer quantity between 1 and 10 before arithmetic.

Control input:

```json
{
  "quantity": 1
}
```

Investigation example after understanding the cause:

```json
{
  "quantity": -1
}
```

## 3. Client-controlled discount · `pay-discount`

The browser supplies a discount percentage that changes the amount due.

Fix: Resolve campaign discounts on the server with a defined ceiling.

Control input:

```json
{
  "discount": 0
}
```

Investigation example after understanding the cause:

```json
{
  "discount": 100
}
```

## 4. Coupon reuse · `pay-coupon-reuse`

A one-use coupon applies repeatedly without a redemption ledger.

Fix: Atomically record redemption by account and coupon; retain the valid first use.

Control input:

```json
{
  "coupon": "WELCOME",
  "repeat": 1
}
```

Investigation example after understanding the cause:

```json
{
  "coupon": "WELCOME",
  "repeat": 2
}
```

## 5. Currency mismatch · `pay-currency`

An amount interpreted in a different currency separates the order from provider settlement.

Fix: Bind provider amount and currency to the stored order.

Control input:

```json
{
  "currency": "USD"
}
```

Investigation example after understanding the cause:

```json
{
  "currency": "JPY"
}
```

## 6. Minor-unit rounding · `pay-rounding`

Converting a tiny decimal charge into integer units can produce zero.

Fix: Use integer minor units and catalog prices; reject values outside the contract.

Control input:

```json
{
  "amount": "100.00"
}
```

Investigation example after understanding the cause:

```json
{
  "amount": "0.004"
}
```

## 7. Browser-calculated total · `pay-total`

The server stores a posted total without recomputing line items.

Fix: Recompute line items, shipping and tax on the server.

Control input:

```json
{
  "total": 10000
}
```

Investigation example after understanding the cause:

```json
{
  "total": 0
}
```

## 8. Shipping fee tampering · `pay-shipping`

An editable shipping field removes a required fee.

Fix: Resolve fees from a trusted shipping method.

Control input:

```json
{
  "shipping": 1000
}
```

Investigation example after understanding the cause:

```json
{
  "shipping": 0
}
```

## 9. Tax field tampering · `pay-tax`

The server trusts the submitted tax value.

Fix: Calculate tax from trusted order data.

Control input:

```json
{
  "tax": 1000
}
```

Investigation example after understanding the cause:

```json
{
  "tax": 0
}
```

## 10. Browser payment status · `pay-status`

A posted paid status promotes an order without settlement.

Fix: Payment state comes only from a trusted provider ledger.

Control input:

```json
{
  "status": "paid",
  "receipt": "settled-order100"
}
```

Investigation example after understanding the cause:

```json
{
  "status": "paid",
  "receipt": "pending-order100"
}
```

## 11. Unverified payment event · `pay-webhook`

A client event claiming settlement is treated as a provider event.

Fix: Verify provider signatures outside client data, then process once.

Control input:

```json
{
  "event": "settled",
  "signature": "DEMO_VALID_SIGNATURE"
}
```

Investigation example after understanding the cause:

```json
{
  "event": "settled",
  "signature": "invalid"
}
```

## 12. Payment amount and order binding · `pay-binding`

A genuine payment for a cheap order settles a different expensive order.

Fix: Verify order ID, amount, currency and merchant before settlement.

Control input:

```json
{
  "payment": "settled-order100"
}
```

Investigation example after understanding the cause:

```json
{
  "payment": "settled-order1"
}
```

## 13. Payment event replay · `pay-replay`

Reprocessing one event grants multiple entitlements.

Fix: Use a trusted idempotency key and atomic event ledger.

Control input:

```json
{
  "event_id": "evt-demo",
  "repeat": 1
}
```

Investigation example after understanding the cause:

```json
{
  "event_id": "evt-demo",
  "repeat": 2
}
```

## 14. Over-refund · `pay-refund`

A refund amount is not compared with remaining captured funds.

Fix: Check cumulative refunds against captured funds in one transaction.

Control input:

```json
{
  "refund": 1000
}
```

Investigation example after understanding the cause:

```json
{
  "refund": 20000
}
```

## 15. Gift credit double spend · `pay-gift`

Each redemption reads the same stale balance snapshot.

Fix: Make balance check and debit atomic; test real concurrent workers in production.

Control input:

```json
{
  "spend": 6000,
  "repeat": 1
}
```

Investigation example after understanding the cause:

```json
{
  "spend": 6000,
  "repeat": 2
}
```

## 16. Trial eligibility across plans · `pay-trial`

Eligibility is keyed only by plan name instead of subscription identity.

Fix: Share trial entitlement across plans for the same synthetic account and payment identity.

Control input:

```json
{
  "plan": "basic",
  "purchase": "paid"
}
```

Investigation example after understanding the cause:

```json
{
  "plan": "premium",
  "purchase": "trial"
}
```

## 17. Read another user’s object · `acl-read`

Knowing an ID or submitting a field is not authorization. This endpoint omits ownership.

Fix: Derive alice and tenant north from the session, then enforce ownership before reading or changing state.

Control input:

```json
{
  "object": "a-1"
}
```

Investigation example after understanding the cause:

```json
{
  "object": "b-1"
}
```

## 18. Update another user’s object · `acl-write`

Knowing an ID or submitting a field is not authorization. This endpoint omits write permission.

Fix: Derive alice and tenant north from the session, then enforce write permission before reading or changing state.

Control input:

```json
{
  "object": "a-1",
  "note": "updated"
}
```

Investigation example after understanding the cause:

```json
{
  "object": "b-1",
  "note": "updated"
}
```

## 19. Delete another user’s object · `acl-delete`

Knowing an ID or submitting a field is not authorization. This endpoint omits delete permission.

Fix: Derive alice and tenant north from the session, then enforce delete permission before reading or changing state.

Control input:

```json
{
  "object": "a-1"
}
```

Investigation example after understanding the cause:

```json
{
  "object": "b-1"
}
```

## 20. Nested object mismatch · `acl-nested`

Knowing an ID or submitting a field is not authorization. This endpoint omits parent-child relationship.

Fix: Derive alice and tenant north from the session, then enforce parent-child relationship before reading or changing state.

Control input:

```json
{
  "parent": "alice",
  "child": "a-1"
}
```

Investigation example after understanding the cause:

```json
{
  "parent": "alice",
  "child": "b-1"
}
```

## 21. Tenant isolation · `acl-tenant`

Knowing an ID or submitting a field is not authorization. This endpoint omits session tenant.

Fix: Derive alice and tenant north from the session, then enforce session tenant before reading or changing state.

Control input:

```json
{
  "tenant": "north",
  "object": "a-1"
}
```

Investigation example after understanding the cause:

```json
{
  "tenant": "south",
  "object": "c-1"
}
```

## 22. Per-item batch authorization · `acl-batch`

Knowing an ID or submitting a field is not authorization. This endpoint omits ownership of every item.

Fix: Derive alice and tenant north from the session, then enforce ownership of every item before reading or changing state.

Control input:

```json
{
  "objects": [
    "a-1"
  ]
}
```

Investigation example after understanding the cause:

```json
{
  "objects": [
    "a-1",
    "b-1"
  ]
}
```

## 23. Export job ownership · `acl-export`

Knowing an ID or submitting a field is not authorization. This endpoint omits export job ownership.

Fix: Derive alice and tenant north from the session, then enforce export job ownership before reading or changing state.

Control input:

```json
{
  "job": "export-alice"
}
```

Investigation example after understanding the cause:

```json
{
  "job": "export-bob"
}
```

## 24. Download reference authorization · `acl-download`

Knowing an ID or submitting a field is not authorization. This endpoint omits file permission at download.

Fix: Derive alice and tenant north from the session, then enforce file permission at download before reading or changing state.

Control input:

```json
{
  "file": "file-alice"
}
```

Investigation example after understanding the cause:

```json
{
  "file": "file-bob"
}
```

## 25. Client-supplied role · `acl-role`

Knowing an ID or submitting a field is not authorization. This endpoint omits server-stored actor role.

Fix: Derive alice and tenant north from the session, then enforce server-stored actor role before reading or changing state.

Control input:

```json
{
  "role": "viewer",
  "action": "view"
}
```

Investigation example after understanding the cause:

```json
{
  "role": "admin",
  "action": "admin"
}
```

## 26. Mass assignment · `acl-mass`

Knowing an ID or submitting a field is not authorization. This endpoint omits an allowlist of editable fields.

Fix: Derive alice and tenant north from the session, then enforce an allowlist of editable fields before reading or changing state.

Control input:

```json
{
  "display_name": "Alice"
}
```

Investigation example after understanding the cause:

```json
{
  "display_name": "Alice",
  "is_admin": true
}
```

## 27. Untrusted forwarded IP · `rate-xff`

A source label supplied by the client creates a new bucket when changed.

Fix: Trust forwarding headers only from configured proxies and retain account budgets.

Control input:

```json
{
  "account": "alice",
  "source": "192.0.2.1",
  "attempts": 4
}
```

Investigation example after understanding the cause:

```json
{
  "account": "alice",
  "source": "192.0.2.2",
  "attempts": 1
}
```

## 28. Distributed-source budget · `rate-ip-pool`

Even a trustworthy network source alone cannot limit attempts distributed against one account.

Fix: Combine account, source and challenge limits; this lab changes labels, never the device IP.

Control input:

```json
{
  "account": "alice",
  "source": "192.0.2.1",
  "attempts": 4
}
```

Investigation example after understanding the cause:

```json
{
  "account": "alice",
  "source": "192.0.2.2",
  "attempts": 4
}
```

## 29. IPv6 canonicalization · `rate-ipv6`

Two spellings of the same address create two raw-string buckets.

Fix: Canonicalize parsed addresses and retain account budgets instead of raw-string comparison.

Control input:

```json
{
  "account": "alice",
  "source": "2001:db8::1",
  "attempts": 4
}
```

Investigation example after understanding the cause:

```json
{
  "account": "alice",
  "source": "2001:0db8:0:0:0:0:0:1",
  "attempts": 1
}
```

## 30. Account normalization · `rate-case`

Authentication treats this fixture email case-insensitively while its bucket does not.

Fix: Use the internal account ID after the same normalization used by authentication.

Control input:

```json
{
  "account": "alice@example.test",
  "attempts": 4
}
```

Investigation example after understanding the cause:

```json
{
  "account": "ALICE@example.test",
  "attempts": 1
}
```

## 31. Alternate-route counters · `rate-route`

Legacy and current routes do not share an attempt budget.

Fix: Share an account policy across every endpoint performing the same operation.

Control input:

```json
{
  "account": "alice",
  "route": "login",
  "attempts": 4
}
```

Investigation example after understanding the cause:

```json
{
  "account": "alice",
  "route": "legacy",
  "attempts": 1
}
```

## 32. Challenge renewal resets budget · `rate-reset`

A fresh challenge ID discards the account’s earlier attempts.

Fix: Do not renew the account attempt budget when issuing a challenge.

Control input:

```json
{
  "account": "alice",
  "challenge": "one",
  "attempts": 4
}
```

Investigation example after understanding the cause:

```json
{
  "account": "alice",
  "challenge": "two",
  "attempts": 1
}
```

## 33. Fixed-window boundary · `rate-window`

Three attempts just before a minute boundary and three just after pass within one second.

Fix: Use a suitable rolling window or token bucket driven by trusted server time.

Control input:

```json
{
  "time": 59,
  "attempts": 3
}
```

Investigation example after understanding the cause:

```json
{
  "time": 60,
  "attempts": 3
}
```

## 34. HTML text · `xss-html`

Input is parsed as HTML nodes instead of text.

Fix: HTML text encoding or textContent.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

## 35. Double-quoted attribute · `xss-attr-double`

A double quote closes the attribute and introduces a new element.

Fix: Encode quoted attributes including both quote characters.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "\"><img src=x onerror=alert(\"BB\")>"
}
```

## 36. Single-quoted attribute · `xss-attr-single`

Encoding only double quotes cannot protect a single-quoted attribute.

Fix: Quote the attribute and encode both quote characters.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "'><img src=x onerror=alert('BB')>"
}
```

## 37. Unquoted attribute · `xss-attr-bare`

Whitespace or a tag delimiter changes the structure of an unquoted attribute.

Fix: Always quote attributes and apply context-specific encoding.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "x><img src=x onerror=alert(\"BB\")>"
}
```

## 38. JavaScript string · `xss-script`

Input terminates a JavaScript string and becomes executable code.

Fix: Avoid generated scripts; serialize data as JSON and escape < for HTML script embedding.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "';alert('BB');//"
}
```

## 39. JavaScript template literal · `xss-template`

A ${...} sequence becomes an expression when a template literal is generated from input.

Fix: Keep input as data instead of interpolating it into executable templates.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "${alert(\"BB\")}"
}
```

## 40. URL scheme context · `xss-url`

HTML escaping alone does not reject a javascript scheme in href.

Fix: Parse URLs and allow only local paths or explicitly approved schemes.

Control input:

```json
{
  "value": "/welcome"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "javascript:alert(\"BB\")"
}
```

## 41. DOM fragment source · `xss-dom-fragment`

A # fragment never reaches HTTP but can reach innerHTML in the browser.

Fix: Use textContent for fragment data.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

## 42. DOM query source: search · `xss-dom-query`

The search parameter reaches innerHTML; the parameter need not be named q.

Fix: Trace the source to its sink and use textContent.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

## 43. Stored comment XSS · `xss-stored`

A stored comment is later rendered as HTML.

Fix: Encode at every rendering sink; storing a string does not sanitize it.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

## 44. Entity decode before DOM sink · `xss-entity`

Decoding HTML entities before innerHTML reconstructs a tag.

Fix: Do not parse decoded text as HTML; use textContent.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "&lt;img src=x onerror=alert(\"BB\")&gt;"
}
```

## 45. Double URL decoding · `xss-double-url`

Two URL-decoding passes turn encoded data into markup.

Fix: Define a single decoding contract and keep final text out of innerHTML.

Control input:

```json
{
  "value": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "value": "%253Cimg%2520src%253Dx%2520onerror%253Dalert(%2522BB%2522)%253E"
}
```

## 46. SQL search injection · `code-sqli`

Concatenating text into SQL changes the owner predicate.

Fix: Use bound parameters with a session-derived ownership predicate.

Control input:

```json
{
  "query": "Alice"
}
```

Investigation example after understanding the cause:

```json
{
  "query": "' OR 1=1 --"
}
```

## 47. NoSQL operator confusion · `code-nosql`

An object is accepted where a string is required and interpreted as $ne.

Fix: Validate field types and never pass client operators to a query.

Control input:

```json
{
  "password": "DEMO_VALID_PASSWORD"
}
```

Investigation example after understanding the cause:

```json
{
  "password": {
    "$ne": null
  }
}
```

## 48. Template expression evaluation · `code-template`

A closed {{7*7}} fixture illustrates mixing data with templates; there is no eval.

Fix: Use a fixed template and pass input only as data.

Control input:

```json
{
  "template": "hello"
}
```

Investigation example after understanding the cause:

```json
{
  "template": "{{7*7}}"
}
```

## 49. Unrestricted redirect decision · `code-redirect`

The next field accepts an external destination without policy. No external navigation occurs.

Fix: Allow specific parsed and normalized local paths.

Control input:

```json
{
  "next": "/welcome"
}
```

Investigation example after understanding the cause:

```json
{
  "next": "https://outside.example/"
}
```

## 50. Synthetic internal fetch · `code-ssrf`

A closed transport fixture exposes an internal response without networking.

Fix: Enforce destination policy and revalidate every redirect before transport.

Control input:

```json
{
  "url": "https://public.lab/welcome"
}
```

Investigation example after understanding the cause:

```json
{
  "url": "http://internal.lab/config"
}
```

## Payload and encoding comparisons

The XSS selector contains three samples per context (36 samples), including negative controls; an inert sample is not general proof of safety. URL inspection checks href policy only because an opaque-origin frame does not establish javascript: execution. The other eleven contexts check an actual browser execution signal.

### `xss-html`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "<svg onload=alert(\"BB\")>"
}
```

Negative control / inert encoding: Percent encoding is not automatically decoded by HTML parsing.

```json
{
  "value": "%3Cimg%20src=x%20onerror=alert(1)%3E"
}
```

### `xss-attr-double`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "\"><img src=x onerror=alert(\"BB\")>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "\"><svg onload=alert(\"BB\")>"
}
```

Negative control / inert encoding: Quote entities are data, not attribute-syntax delimiters.

```json
{
  "value": "&quot;&gt;&lt;svg onload=alert(\"BB\")&gt;"
}
```

### `xss-attr-single`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "'><img src=x onerror=alert('BB')>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "'><svg onload=alert(\"BB\")>"
}
```

Negative control / inert encoding: An encoded quote stays inside the attribute value.

```json
{
  "value": "&#39;&gt;&lt;img src=x onerror=alert(1)&gt;"
}
```

### `xss-attr-bare`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "x><img src=x onerror=alert(\"BB\")>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "x><svg onload=alert(\"BB\")>"
}
```

Negative control / inert encoding: A control does not introduce a new attribute or node.

```json
{
  "value": "hello"
}
```

### `xss-script`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "';alert('BB');//"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "';alert(String.fromCharCode(66,66));//"
}
```

Negative control / inert encoding: This sink does not URL-decode before emitting the JavaScript string.

```json
{
  "value": "%27;alert(1);//"
}
```

### `xss-template`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "${alert(\"BB\")}"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "`;alert('BB');//"
}
```

Negative control / inert encoding: Percent-encoded text remains data in this context.

```json
{
  "value": "%24%7Balert(1)%7D"
}
```

### `xss-url`

Primary payload: Inspect href in the evidence; this is a scheme-policy check, not execution proof inside the frame.

```json
{
  "value": "javascript:alert(\"BB\")"
}
```

Second context-specific form: Inspect href in the evidence; this is a scheme-policy check, not execution proof inside the frame.

```json
{
  "value": "JaVaScRiPt:alert('BB')"
}
```

Negative control / inert encoding: Inspect href in the evidence; this is a scheme-policy check, not execution proof inside the frame.

```json
{
  "value": "/welcome"
}
```

### `xss-dom-fragment`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "<svg onload=alert(\"BB\")>"
}
```

Negative control / inert encoding: A script element inserted by innerHTML does not execute automatically; innerHTML is still unsafe.

```json
{
  "value": "<script>alert(\"BB\")</script>"
}
```

### `xss-dom-query`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "<svg onload=alert(\"BB\")>"
}
```

Negative control / inert encoding: A script element alone is not execution proof for innerHTML.

```json
{
  "value": "<script>alert(\"BB\")</script>"
}
```

### `xss-stored`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "<script>alert(\"BB\")</script>"
}
```

Negative control / inert encoding: Entity text renders as text without an additional decoding stage in this case.

```json
{
  "value": "&lt;img src=x onerror=alert(1)&gt;"
}
```

### `xss-entity`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "&lt;img src=x onerror=alert(\"BB\")&gt;"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "&#60;img src=x onerror=alert(\"BB\")&#62;"
}
```

Negative control / inert encoding: An extra entity layer remains text after one decode followed by HTML parsing.

```json
{
  "value": "&amp;lt;img src=x onerror=alert(1)&amp;gt;"
}
```

### `xss-double-url`

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{
  "value": "%253Cimg%2520src%253Dx%2520onerror%253Dalert(%2522BB%2522)%253E"
}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{
  "value": "%3Cimg%20src%3Dx%20onerror%3Dalert%28%22BB%22%29%3E"
}
```

Negative control / inert encoding: A triple-encoded input remains encoded after two decoding passes.

```json
{
  "value": "%25253Cimg%252520src%25253Dx%252520onerror%25253Dalert%252528%252522BB%252522%252529%25253E"
}
```


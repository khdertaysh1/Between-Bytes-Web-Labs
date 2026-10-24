# Between Bytes · Five application labs · 0.9

The home page groups 50 cases into five labs: payments (16), XSS (12), authorization (10), rate limits (7) and code services (5). Open `http://127.0.0.1:8000/` or `/academy`. The original foundation rooms remain at `/foundations`. Every case is open, without points.

## Actual requests and responses

Choose a lab, then a case in its internal map. Each case has vulnerable and fixed variants with independent server state so unrelated flaws do not contaminate one investigation. The JSON editor sends that body to the application route shown in the HTTP preview, without a case/input wrapper. An actual X-Forwarded-For header carries the lab source label when applicable. The device IP does not change.

```http
POST /academy/api/payment/pay-binding/fixed HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/json

{"payment":"settled-order1"}
```

The server returns an actual HTTP 409 with error.code=payment_order_mismatch, not a 200 containing status=409 in JSON. It includes X-Request-ID and an ETag for the stored order. Classroom checks and flags come from `/academy/evidence`, separate from the business response.

## What the checkout actually executes locally

The engine persists an order, line items, currency and totals, captured/refunded amounts, transactions, download entitlements, gift balance and subscriptions. A separate GET to `/academy/resource?case=pay-binding&mode=fixed` reads current state; revision advances for an accepted mutation and stays unchanged for a rejection. Transaction history is capped at 80 entries and subscriptions at 20. Monetary amounts are integer minor units.

From a fresh round, test the mismatched receipt against each variant, read the resource after each request, then submit the correct fixed receipt. Rejecting a later invalid request must not roll back an earlier valid settlement. A quote change alone does not capture funds or establish a free purchase.

Provider receipts are seeded local records; webhook verification computes an actual HMAC-SHA256 for a fixed canonical event. The published control includes a valid lab signature. There are no cards, external payment gateways or real funds. This is not a production provider protocol or a transactional distributed database. Gift credit uses a deterministic stale-read schedule, not a live network-race test.

## Other application labs

Authorization uses invoices, tenants and a server-defined Alice identity. Updates and deletions mutate round data; fixed operations reject before mutation without exposing denied content. Rate limiting returns 401 when a failed attempt reaches verification and 429 when throttled, with Retry-After and RateLimit-Remaining. The exercise budget is three attempts; source addresses are documentation ranges and the boundary exercise uses an explicit lab clock.

XSS includes eleven execution contexts in an opaque-origin iframe with CSP blocking external resources and connections, plus a URL case inspecting href policy without claiming execution. Its 36 samples include deliberately inert controls. Stored XSS persists a comment before a separate rendering GET; DOM cases read actual location.hash and search values. An alert signal replaces a dialog; absence during a bounded observation window cannot establish the absence of all XSS.

SQLi runs real in-memory SQLite. NoSQL evaluates a bounded local document predicate; the template renderer parses limited arithmetic without eval. SSRF and redirect exercises use closed resources and policies without DNS or external transport. Completion marks and flags are learning aids, not certificates or tamper-resistant exams.

## Payment lab

### Client-controlled price · `pay-price`

The Web Security Course catalog price is $100. The browser sends price=10000 in cents while updating the quote. You are not changing the catalog; you are testing whether the server mistakes a browser value for an authoritative price.

The server trusts a submitted unit price instead of its product catalog.

Compare items[0].unit_amount and totals.amount_due with the catalog price. A one-cent quote establishes price tampering, not successful settlement or a free purchase.

Vulnerable logic:

```python
unit_price = body["price"]
```

Repaired logic:

```python
unit_price = catalog["SEC-COURSE"].price
```

Resolve the price from the server catalog; ignore client prices.

Control request:

```json
{
  "price": 10000
}
```

Investigation request:

```json
{
  "price": 1
}
```

### Negative quantities · `pay-quantity`

The cart permits one to ten course seats. Submit quantity=-1 directly to the quote endpoint. A browser constraint may stop the UI, but only the server contract defines a valid quantity.

A negative quantity turns a charge into synthetic credit.

A negative total is an invalid accounting state that could reach later stages. The fixed endpoint returns 422 without mutating the prior order. Try quantity=2: two seats must cost $200.

Vulnerable logic:

```python
total = unit_price * body["quantity"]
```

Repaired logic:

```python
require_integer_between(quantity, 1, 10)
total = catalog_price * quantity
```

Require an integer quantity between 1 and 10 before arithmetic.

Control request:

```json
{
  "quantity": 1
}
```

Investigation request:

```json
{
  "quantity": -1
}
```

### Client-controlled discount · `pay-discount`

The cart supports campaign discounts. The UI displays a percentage but cannot authorize it. Posting discount=100 tests whether the pricing service takes discount policy from the client.

The browser supplies a discount percentage that changes the amount due.

Inspect totals.discount and amount_due. A zero quote is a pricing violation here; changing a quote alone does not settle a provider payment or grant a download.

Vulnerable logic:

```python
discount = body["discount"]
```

Repaired logic:

```python
discount = active_campaign.allowed_discount(customer)
```

Resolve campaign discounts on the server with a defined ceiling.

Control request:

```json
{
  "discount": 0
}
```

Investigation request:

```json
{
  "discount": 100
}
```

### Coupon reuse · `pay-coupon-reuse`

WELCOME grants a $20 discount once per customer. Redeem it repeatedly within one round. The bounded repeat field schedules multiple local operations so you can inspect repeated-request effects.

A one-use coupon applies repeatedly without a redemption ledger.

Each redemption creates a coupon_redeemed transaction. The vulnerable ledger keeps increasing both the count and discount. The fix keeps redemptions=1 and the quote at $80, even when a repeated request returns 200.

Vulnerable logic:

```python
apply_discount(code)  # no redemption record
```

Repaired logic:

```python
atomic: redeem_once(customer_id, coupon_id)
```

Atomically record redemption by account and coupon; retain the valid first use.

Control request:

```json
{
  "coupon": "WELCOME",
  "repeat": 1
}
```

Investigation request:

```json
{
  "coupon": "WELCOME",
  "repeat": 2
}
```

### Currency mismatch · `pay-currency`

The order is USD 100.00. Processor settlement contains both amount and currency, not just a number. This case tests a numeric amount comparison that omits currency when JPY is supplied.

An amount interpreted in a different currency separates the order from provider settlement.

In the vulnerable variant inspect fulfilment_released and its provider currency. Do not equate JPY units with USD units. The fix must return 409 currency_mismatch without advancing revision.

Vulnerable logic:

```python
if payment.amount == order.amount: fulfil()
```

Repaired logic:

```python
require(payment.currency == order.currency)
require(payment.amount == order.amount)
```

Bind provider amount and currency to the stored order.

Control request:

```json
{
  "currency": "USD"
}
```

Investigation request:

```json
{
  "currency": "JPY"
}
```

### Minor-unit rounding · `pay-rounding`

A legacy interface accepts amount as a decimal string while accounting uses cents. Truncating 0.004 to integer minor units produces zero.

Converting a tiny decimal charge into integer units can produce zero.

Compare amount_due with the catalog value 10000. Try 99.999 to inspect truncation too. Randomly adding round is not the fix: product prices must be server-derived and every interface must declare its monetary unit.

Vulnerable logic:

```python
amount_minor = int(Decimal(body["amount"]) * 100)
```

Repaired logic:

```python
amount_minor = catalog_price_minor  # integer contract
```

Use integer minor units and catalog prices; reject values outside the contract.

Control request:

```json
{
  "amount": "100.00"
}
```

Investigation request:

```json
{
  "amount": "0.004"
}
```

### Browser-calculated total · `pay-total`

The browser adds cart lines and displays total before confirmation. This number is presentation data. The server must compute line prices, quantities and trusted fees rather than persist the posted sum.

The server stores a posted total without recomputing line items.

Change total to zero, then read the order again. A changed totals.amount_due alongside a 10000 course line proves an inconsistent persisted order. A changed display alone would not be sufficient evidence.

Vulnerable logic:

```python
order.total = body["total"]
```

Repaired logic:

```python
order.total = sum(trusted_lines) + shipping + tax - discount
```

Recompute line items, shipping and tax on the server.

Control request:

```json
{
  "total": 10000
}
```

Investigation request:

```json
{
  "total": 0
}
```

### Shipping fee tampering · `pay-shipping`

This cart has a fixed $10 delivery charge. Shipping should come from pricing policy and the selected delivery method, not a hidden form field. Test removal with shipping=0.

An editable shipping field removes a required fee.

Evidence is a $100 quote instead of $110 while the delivery service is unchanged. The fix recalculates the fee. Do not apply this policy blindly to digital goods or legitimate free-shipping offers.

Vulnerable logic:

```python
shipping = body["shipping"]
```

Repaired logic:

```python
shipping = delivery_policy.quote(selected_method)
```

Resolve fees from a trusted shipping method.

Control request:

```json
{
  "shipping": 1000
}
```

Investigation request:

```json
{
  "shipping": 0
}
```

### Tax field tampering · `pay-tax`

This exercise uses a fixed $10 tax to keep the policy inspectable. A client may submit a displayed value but cannot decide whether the transaction is exempt. Test tax=0 against the same order.

The server trusts the submitted tax value.

Inspect totals.tax and amount_due. A real application needs jurisdiction, product and documented exemption rules; this case does not implement a full legal tax system.

Vulnerable logic:

```python
tax = body["tax"]
```

Repaired logic:

```python
tax = tax_policy.calculate(trusted_order_context)
```

Calculate tax from trusted order data.

Control request:

```json
{
  "tax": 1000
}
```

Investigation request:

```json
{
  "tax": 0
}
```

### Browser payment status · `pay-status`

After returning from checkout, the browser posts a visible paid status and receipt reference. In a fresh round pending-order100 is still pending in the local provider ledger. The flaw promotes the order based on browser state.

A posted paid status promotes an order without settlement.

Start with the unsettled example, then read the order: the vulnerable version can show paid and one download while captured_amount=0. The fix returns 409. Then use the settled receipt: the model records capture and grants one entitlement.

Vulnerable logic:

```python
if body["status"] == "paid": release_download()
```

Repaired logic:

```python
receipt = provider_ledger.lookup(receipt_id)
require(receipt.status == "settled")
```

Payment state comes only from a trusted provider ledger.

Control request:

```json
{
  "status": "paid",
  "receipt": "settled-order100"
}
```

Investigation request:

```json
{
  "status": "paid",
  "receipt": "pending-order100"
}
```

### Unverified payment event · `pay-webhook`

The payment service receives a settled event from a local provider fixture. The new implementation actually checks HMAC-SHA256 over a server-defined canonical event. The control includes a valid signature for that event only; invalid represents an untrusted notification.

A client event claiming settlement is treated as a provider event.

The vulnerable route can grant an entitlement with zero captured funds. The fix returns 401 for a bad signature without changing the ledger. This is a fixed lab contract, not Stripe or Adyen: production verification must follow the provider’s raw-body, timestamp and replay contract.

Vulnerable logic:

```python
if event == "settled": fulfil(order)
```

Repaired logic:

```python
require_constant_time_hmac(canonical_event, signature)
apply_verified_event_once()
```

Verify provider signatures outside client data, then process once.

Control request:

```json
{
  "event": "settled",
  "signature": "53ad32f960cb08a9887152a7542d36f80df5b92d831e9af5b6e3c29f459ff812"
}
```

Investigation request:

```json
{
  "event": "settled",
  "signature": "invalid"
}
```

### Payment amount and order binding · `pay-binding`

You have order100 worth $100 and a genuine settled-order1 receipt for a different $1 order. A successful receipt is insufficient unless it belongs to the current order.

A genuine payment for a cheap order settles a different expensive order.

From a fresh round compare order.id with payment_order, then captured_amount with amount_due. The vulnerable implementation grants a download for $1. The fix returns 409 without increasing revision. Submit settled-order100 afterward to prove legitimate settlement still works.

Vulnerable logic:

```python
if receipt.status == "settled": fulfil(order)
```

Repaired logic:

```python
require(receipt.order_id == order.id)
require(receipt.amount == order.total and receipt.currency == order.currency)
```

Verify order ID, amount, currency and merchant before settlement.

Control request:

```json
{
  "payment": "settled-order100"
}
```

Investigation request:

```json
{
  "payment": "settled-order1"
}
```

### Payment event replay · `pay-replay`

Event evt-demo grants one course download. Providers legitimately retry notifications after network failures. The requirement is idempotent processing rather than rejecting every repeated notification.

Reprocessing one event grants multiple entitlements.

Replay the same event_id and inspect entitlements.downloads and entitlement_granted entries. The fix can return 200 with idempotent_replay=true while creating neither another transaction nor a second entitlement.

Vulnerable logic:

```python
on_event(): entitlements += 1
```

Repaired logic:

```python
atomic: if event_id not in processed: grant_and_record(event_id)
```

Use a trusted idempotency key and atomic event ledger.

Control request:

```json
{
  "event_id": "evt-demo",
  "repeat": 1
}
```

Investigation request:

```json
{
  "event_id": "evt-demo",
  "repeat": 2
}
```

### Over-refund · `pay-refund`

The order has $100 captured. Refund $10, then request $200. Protection must cover cumulative refunds, not just validate each request independently.

A refund amount is not compared with remaining captured funds.

Inspect refunded_amount and refund_created entries. The vulnerable path lets refunds exceed capture. The fix returns 409 while preserving revision and amount; repeated small refunds must not exceed the remaining balance either.

Vulnerable logic:

```python
create_refund(requested_amount)
```

Repaired logic:

```python
atomic: require(refunded + requested <= captured)
create_refund_and_update_balance()
```

Check cumulative refunds against captured funds in one transaction.

Control request:

```json
{
  "refund": 1000
}
```

Investigation request:

```json
{
  "refund": 20000
}
```

### Gift credit double spend · `pay-gift`

A gift card holds $100 and two workers each try to spend $60. To reproduce the concurrency error deterministically, the vulnerable schedule gives both workers the same pre-debit balance.

Each redemption reads the same stale balance snapshot.

The invalid result is a -$20 balance with two gift_debited entries. The fix permits one debit and leaves $40. This is a deterministic schedule, not a database-lock test or proof of concurrency safety on distributed workers.

Vulnerable logic:

```python
balance_snapshot = balance
for worker: if snapshot >= spend: debit(spend)
```

Repaired logic:

```python
atomic: if current_balance >= spend: decrement(spend)
```

Make balance check and debit atomic; test real concurrent workers in production.

Control request:

```json
{
  "spend": 6000,
  "repeat": 1
}
```

Investigation request:

```json
{
  "spend": 6000,
  "repeat": 2
}
```

### Trial eligibility across plans · `pay-trial`

A customer has consumed a basic trial and requests a premium trial. If eligibility is tracked per plan, changing plans becomes a route to a second trial for the same identity.

Eligibility is keyed only by plan name instead of subscription identity.

Inspect subscriptions and trialing status; a visible trial button is not evidence. The fix returns 409 for the second trial but permits a paid subscription. Shared payment-identity and billing policy require product decisions beyond this model.

Vulnerable logic:

```python
eligible = not trials_used[customer, plan]
```

Repaired logic:

```python
eligible = not trials_used[customer, product_family]
```

Share trial entitlement across plans for the same synthetic account and payment identity.

Control request:

```json
{
  "plan": "basic",
  "purchase": "paid"
}
```

Investigation request:

```json
{
  "plan": "premium",
  "purchase": "trial"
}
```

## XSS lab

### HTML text · `xss-html`

Input appears between tags in a search results page. Raw rendering creates an img node and an onerror handler; matching text in JSON or an HTML entity is not equivalent to execution.

Input is parsed as HTML nodes instead of text.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
output = "<div>" + value + "</div>"
```

Repaired logic:

```python
output = "<div>" + html_escape(value) + "</div>"
```

HTML text encoding or textContent.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "<img src=x onerror=alert(\"BB\")>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "<svg onload=alert(\"BB\")>"}
```

Negative control / inert encoding: Percent encoding is not automatically decoded by HTML parsing.

```json
{"value": "%3Cimg%20src=x%20onerror=alert(1)%3E"}
```

### Double-quoted attribute · `xss-attr-double`

The page repopulates a search input inside value="...". A payload must first close the double quote; ordinary HTML markup may otherwise remain an attribute value.

A double quote closes the attribute and introduces a new element.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
html = '<input value="' + value + '">'
```

Repaired logic:

```python
html = '<input value="' + escape_attribute(value) + '">'
```

Encode quoted attributes including both quote characters.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "\"><img src=x onerror=alert(\"BB\")>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "\"><img src=x onerror=alert(\"BB\")>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "\"><svg onload=alert(\"BB\")>"}
```

Negative control / inert encoding: Quote entities are data, not attribute-syntax delimiters.

```json
{"value": "&quot;&gt;&lt;svg onload=alert(\"BB\")&gt;"}
```

### Single-quoted attribute · `xss-attr-single`

The reflection sits inside a single-quoted attribute. Escaping only double quotes leaves this boundary open, while a quote entity is not an attribute delimiter during parsing.

Encoding only double quotes cannot protect a single-quoted attribute.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
html = "<input value='" + value + "'>"
```

Repaired logic:

```python
html = quote_and_escape_attribute(value)
```

Quote the attribute and encode both quote characters.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "'><img src=x onerror=alert('BB')>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "'><img src=x onerror=alert('BB')>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "'><svg onload=alert(\"BB\")>"}
```

Negative control / inert encoding: An encoded quote stays inside the attribute value.

```json
{"value": "&#39;&gt;&lt;img src=x onerror=alert(1)&gt;"}
```

### Unquoted attribute · `xss-attr-bare`

A legacy template emits an unquoted value attribute. Whitespace or > can terminate it; blocking a particular quote cannot protect an unquoted context.

Whitespace or a tag delimiter changes the structure of an unquoted attribute.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
html = "<input value=" + value + ">"
```

Repaired logic:

```python
html = '<input value="' + escape_attribute(value) + '">'
```

Always quote attributes and apply context-specific encoding.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "x><img src=x onerror=alert(\"BB\")>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "x><img src=x onerror=alert(\"BB\")>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "x><svg onload=alert(\"BB\")>"}
```

Negative control / inert encoding: A control does not introduce a new attribute or node.

```json
{"value": "hello"}
```

### JavaScript string · `xss-script`

A template embeds the search term in a single-quoted JavaScript string. A delimiter can switch data into a statement; HTML escaping is not a JavaScript encoding contract.

Input terminates a JavaScript string and becomes executable code.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
script = "const input='" + value + "';"
```

Repaired logic:

```python
script = "const input=" + script_safe_json(value)
```

Avoid generated scripts; serialize data as JSON and escape < for HTML script embedding.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "';alert('BB');//"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "';alert('BB');//"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "';alert(String.fromCharCode(66,66));//"}
```

Negative control / inert encoding: This sink does not URL-decode before emitting the JavaScript string.

```json
{"value": "%27;alert(1);//"}
```

### JavaScript template literal · `xss-template`

The UI generates a backtick template literal. In this context ${...} evaluates an expression without requiring an HTML-tag payload.

A ${...} sequence becomes an expression when a template literal is generated from input.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
script = "const input=`" + value + "`;"
```

Repaired logic:

```python
script = "const input=" + script_safe_json(value)
```

Keep input as data instead of interpolating it into executable templates.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "${alert(\"BB\")}"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "${alert(\"BB\")}"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "`;alert('BB');//"}
```

Negative control / inert encoding: Percent-encoded text remains data in this context.

```json
{"value": "%24%7Balert(1)%7D"}
```

### URL scheme context · `xss-url`

A return page builds a link from input. HTML escaping protects attribute syntax but does not decide whether javascript is an allowed scheme. This sandbox checks the resulting link policy without claiming execution.

HTML escaping alone does not reject a javascript scheme in href. In this frame we inspect href and scheme policy only, without claiming javascript: execution.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
href = html_escape(value)
```

Repaired logic:

```python
href = allow_local_path(parse_url(value))
```

Parse URLs and allow only local paths or explicitly approved schemes.

Control request:

```json
{
  "value": "/welcome"
}
```

Investigation request:

```json
{
  "value": "javascript:alert(\"BB\")"
}
```

Primary payload: Inspect href in the evidence; this is a scheme-policy check, not execution proof inside the frame.

```json
{"value": "javascript:alert(\"BB\")"}
```

Second context-specific form: Inspect href in the evidence; this is a scheme-policy check, not execution proof inside the frame.

```json
{"value": "JaVaScRiPt:alert('BB')"}
```

Negative control / inert encoding: Inspect href in the evidence; this is a scheme-policy check, not execution proof inside the frame.

```json
{"value": "/welcome"}
```

### DOM fragment source · `xss-dom-fragment`

A preview reads the part after # in its own URL. The fragment is not sent in HTTP, but client JavaScript decodes it into innerHTML. Evidence belongs in the DOM and browser, not a server-response reflection.

A # fragment never reaches HTTP but can reach innerHTML in the browser.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
output.innerHTML = decodeURIComponent(location.hash.slice(1))
```

Repaired logic:

```python
output.textContent = decodeURIComponent(location.hash.slice(1))
```

Use textContent for fragment data.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "<img src=x onerror=alert(\"BB\")>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "<svg onload=alert(\"BB\")>"}
```

Negative control / inert encoding: A script element inserted by innerHTML does not execute automatically; innerHTML is still unsafe.

```json
{"value": "<script>alert(\"BB\")</script>"}
```

### DOM query source: search · `xss-dom-query`

The preview reads a search parameter rather than q. Looking for one parameter name misses other data flows; trace URLSearchParams to the innerHTML sink.

The search parameter reaches innerHTML; the parameter need not be named q.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
output.innerHTML = new URLSearchParams(location.search).get("search")
```

Repaired logic:

```python
output.textContent = new URLSearchParams(location.search).get("search")
```

Trace the source to its sink and use textContent.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "<img src=x onerror=alert(\"BB\")>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "<svg onload=alert(\"BB\")>"}
```

Negative control / inert encoding: A script element alone is not execution proof for innerHTML.

```json
{"value": "<script>alert(\"BB\")</script>"}
```

### Stored comment XSS · `xss-stored`

A customer posts a comment stored in the server round. A later, separate GET renders it. The flaw is unescaped rendering, not merely accepting text at the storage endpoint.

A stored comment is later rendered as HTML.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
store(comment); later_render_as_html(comment)
```

Repaired logic:

```python
store(comment); escape_at_each_output_sink(comment)
```

Encode at every rendering sink; storing a string does not sanitize it.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "<img src=x onerror=alert(\"BB\")>"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "<img src=x onerror=alert(\"BB\")>"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "<script>alert(\"BB\")</script>"}
```

Negative control / inert encoding: Entity text renders as text without an additional decoding stage in this case.

```json
{"value": "&lt;img src=x onerror=alert(1)&gt;"}
```

### Entity decode before DOM sink · `xss-entity`

The processing chain decodes HTML entities before assigning to innerHTML. An &lt;...&gt; input becomes markup after decoding, while an extra encoding layer may remain text.

Decoding HTML entities before innerHTML reconstructs a tag.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
output.innerHTML = decode_entities(input)
```

Repaired logic:

```python
output.textContent = decode_entities(input)
```

Do not parse decoded text as HTML; use textContent.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "&lt;img src=x onerror=alert(\"BB\")&gt;"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "&lt;img src=x onerror=alert(\"BB\")&gt;"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "&#60;img src=x onerror=alert(\"BB\")&#62;"}
```

Negative control / inert encoding: An extra entity layer remains text after one decode followed by HTML parsing.

```json
{"value": "&amp;lt;img src=x onerror=alert(1)&amp;gt;"}
```

### Double URL decoding · `xss-double-url`

Two stages URL-decode in sequence: %253C becomes %3C, then <. Inspecting text before the full transformation does not describe what reaches the sink.

Two URL-decoding passes turn encoded data into markup.

Record the source, decoding stages, output context and frame evidence. Reflection or a visible tag alone is not execution proof. Try the negative control and explain why it remains inert in this particular sink.

Vulnerable logic:

```python
output.innerHTML = decode_url(decode_url(input))
```

Repaired logic:

```python
output.textContent = decode_according_to_contract(input)
```

Define a single decoding contract and keep final text out of innerHTML.

Control request:

```json
{
  "value": "hello"
}
```

Investigation request:

```json
{
  "value": "%253Cimg%2520src%253Dx%2520onerror%253Dalert(%2522BB%2522)%253E"
}
```

Primary payload: Observe vulnerable execution and compare the fixed rendering.

```json
{"value": "%253Cimg%2520src%253Dx%2520onerror%253Dalert(%2522BB%2522)%253E"}
```

Second context-specific form: A different spelling still needs a matching sink context.

```json
{"value": "%3Cimg%20src%3Dx%20onerror%3Dalert%28%22BB%22%29%3E"}
```

Negative control / inert encoding: A triple-encoded input remains encoded after two decoding passes.

```json
{"value": "%25253Cimg%252520src%25253Dx%252520onerror%25253Dalert%252528%252522BB%252522%252529%25253E"}
```

## Authorization lab

### Read another user’s object · `acl-read`

The invoice page opens Alice’s a-1 document. Substitute b-1 while keeping the same session; Bob owns it within the same tenant.

Knowing an ID or submitting a field is not authorization. This endpoint omits ownership.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
GET invoice by id → return document
```

Repaired logic:

```python
SELECT ... WHERE id=? AND owner_id=session.user_id
```

Derive alice and tenant north from the session, then enforce ownership before reading or changing state.

Control request:

```json
{
  "object": "a-1"
}
```

Investigation request:

```json
{
  "object": "b-1"
}
```

### Update another user’s object · `acl-write`

The invoice-note endpoint accepts object and note. Change Bob’s b-1 note and inspect the updated document. Read and write are distinct operations and require separate permissions.

Knowing an ID or submitting a field is not authorization. This endpoint omits write permission.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
document.note = body.note
```

Repaired logic:

```python
require(can_write(session.actor, document))
document.note = body.note
```

Derive alice and tenant north from the session, then enforce write permission before reading or changing state.

Control request:

```json
{
  "object": "a-1",
  "note": "updated"
}
```

Investigation request:

```json
{
  "object": "b-1",
  "note": "updated"
}
```

### Delete another user’s object · `acl-delete`

A deletion endpoint must authorize the actor before removing an object. Sending b-1 is destructive within the exercise state: the resource disappears and a repeated deletion returns 404.

Knowing an ID or submitting a field is not authorization. This endpoint omits delete permission.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
delete_by_id(body.object)
```

Repaired logic:

```python
require(can_delete(actor, document))
delete_by_id(document.id)
```

Derive alice and tenant north from the session, then enforce delete permission before reading or changing state.

Control request:

```json
{
  "object": "a-1"
}
```

Investigation request:

```json
{
  "object": "b-1"
}
```

### Nested object mismatch · `acl-nested`

A route such as /customers/alice/invoices/:child does not guarantee that child belongs to Alice. Use an allowed parent with Bob’s child: parent-only authorization leaves the nested resource exposed.

Knowing an ID or submitting a field is not authorization. This endpoint omits parent-child relationship.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
authorize(parent); load(child)
```

Repaired logic:

```python
child = load_where(id=child_id, parent=authorized_parent)
```

Derive alice and tenant north from the session, then enforce parent-child relationship before reading or changing state.

Control request:

```json
{
  "parent": "alice",
  "child": "a-1"
}
```

Investigation request:

```json
{
  "parent": "alice",
  "child": "b-1"
}
```

### Tenant isolation · `acl-tenant`

The B2B application fixes Alice’s tenant as north in the session. The client posts tenant=south and c-1. A tenant field cannot move the session into another organization.

Knowing an ID or submitting a field is not authorization. This endpoint omits session tenant.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
lookup(body.tenant, body.object)
```

Repaired logic:

```python
lookup(session.tenant_id, authorized_object_id)
```

Derive alice and tenant north from the session, then enforce session tenant before reading or changing state.

Control request:

```json
{
  "tenant": "north",
  "object": "a-1"
}
```

Investigation request:

```json
{
  "tenant": "south",
  "object": "c-1"
}
```

### Per-item batch authorization · `acl-batch`

The export service accepts a list of document IDs. Put Bob’s b-1 after the allowed a-1: authorizing the first item or the endpoint itself does not authorize every returned item.

Knowing an ID or submitting a field is not authorization. This endpoint omits ownership of every item.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
authorize(ids[0]); return load_all(ids)
```

Repaired logic:

```python
authorize_every_item_or_reject_batch(ids, actor)
```

Derive alice and tenant north from the session, then enforce ownership of every item before reading or changing state.

Control request:

```json
{
  "objects": [
    "a-1"
  ]
}
```

Investigation request:

```json
{
  "objects": [
    "a-1",
    "b-1"
  ]
}
```

### Export job ownership · `acl-export`

A background export job created by Bob produces a report. Knowing export-bob must not grant Alice its output even when she can use the export endpoint.

Knowing an ID or submitting a field is not authorization. This endpoint omits export job ownership.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
return jobs[job_id].result
```

Repaired logic:

```python
require(job.owner_id == session.user_id)
return job.result
```

Derive alice and tenant north from the session, then enforce export job ownership before reading or changing state.

Control request:

```json
{
  "job": "export-alice"
}
```

Investigation request:

```json
{
  "job": "export-bob"
}
```

### Download reference authorization · `acl-download`

Invoice downloads use references file-alice and file-bob. Random or hard-to-guess references cannot replace authorization when the file is served.

Knowing an ID or submitting a field is not authorization. This endpoint omits file permission at download.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
return storage[file_id]
```

Repaired logic:

```python
require(can_download(actor, file_metadata))
stream_file(file_metadata)
```

Derive alice and tenant north from the session, then enforce file permission at download before reading or changing state.

Control request:

```json
{
  "file": "file-alice"
}
```

Investigation request:

```json
{
  "file": "file-bob"
}
```

### Client-supplied role · `acl-role`

Alice’s session has a viewer role. A client posts action=admin and role=admin; the defect reads the claimed role from the request instead of trusted user state.

Knowing an ID or submitting a field is not authorization. This endpoint omits server-stored actor role.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
if body.role == "admin": show_admin()
```

Repaired logic:

```python
if session.actor.role == "admin": show_admin()
```

Derive alice and tenant north from the session, then enforce server-stored actor role before reading or changing state.

Control request:

```json
{
  "role": "viewer",
  "action": "view"
}
```

Investigation request:

```json
{
  "role": "admin",
  "action": "admin"
}
```

### Mass assignment · `acl-mass`

The profile form should edit display_name. Add is_admin=true to JSON: binding every request field to the user object may write a protected field the UI never displayed.

Knowing an ID or submitting a field is not authorization. This endpoint omits an allowlist of editable fields.

Keep the actor as Alice, then inspect the returned owner or persisted change. HTTP success alone is insufficient. The fix must deny the unauthorized resource while preserving legitimate operations on Alice’s resources.

Vulnerable logic:

```python
profile.update(request.json)
```

Repaired logic:

```python
profile.update(allow_fields(request.json, ["display_name"]))
```

Derive alice and tenant north from the session, then enforce an allowlist of editable fields before reading or changing state.

Control request:

```json
{
  "display_name": "Alice"
}
```

Investigation request:

```json
{
  "display_name": "Alice",
  "is_admin": true
}
```

## Rate-limit lab

### Untrusted forwarded IP · `rate-xff`

The limiter trusts client-supplied X-Forwarded-For. After exhausting 192.0.2.1, send 192.0.2.2. The question is whether the budget identity changes without changing the account.

A source label supplied by the client creates a new bucket when changed.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
bucket = header["X-Forwarded-For"]
```

Repaired logic:

```python
bucket = normalized_account_id; trusted_peer_policy()
```

Trust forwarding headers only from configured proxies and retain account budgets.

Control request:

```json
{
  "account": "alice",
  "source": "192.0.2.1",
  "attempts": 4
}
```

Investigation request:

```json
{
  "account": "alice",
  "source": "192.0.2.2",
  "attempts": 1
}
```

### Distributed-source budget · `rate-ip-pool`

Even trustworthy network addresses can distribute attempts against one identity. This case counts the same account across local source labels without operating proxies.

Even a trustworthy network source alone cannot limit attempts distributed against one account.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
limit_by(source_ip)
```

Repaired logic:

```python
limit_by(account_id) and limit_by(trusted_source)
```

Combine account, source and challenge limits; this lab changes labels, never the device IP.

Control request:

```json
{
  "account": "alice",
  "source": "192.0.2.1",
  "attempts": 4
}
```

Investigation request:

```json
{
  "account": "alice",
  "source": "192.0.2.2",
  "attempts": 4
}
```

### IPv6 canonicalization · `rate-ipv6`

2001:db8::1 and 2001:0db8:0:0:0:0:0:1 represent the same address. Raw-string buckets split the identity; canonicalize addresses and account identity before constructing keys.

Two spellings of the same address create two raw-string buckets.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
bucket = raw_address_string
```

Repaired logic:

```python
bucket = canonical_account_id; canonicalize_ip(source)
```

Canonicalize parsed addresses and retain account budgets instead of raw-string comparison.

Control request:

```json
{
  "account": "alice",
  "source": "2001:db8::1",
  "attempts": 4
}
```

Investigation request:

```json
{
  "account": "alice",
  "source": "2001:0db8:0:0:0:0:0:1",
  "attempts": 1
}
```

### Account normalization · `rate-case`

Authentication in this case treats email case-insensitively, but the vulnerable limiter does not. Exhaust alice@example.test, then use ALICE@example.test.

Authentication treats this fixture email case-insensitively while its bucket does not.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
bucket = raw_email
```

Repaired logic:

```python
bucket = resolved_internal_account_id
```

Use the internal account ID after the same normalization used by authentication.

Control request:

```json
{
  "account": "alice@example.test",
  "attempts": 4
}
```

Investigation request:

```json
{
  "account": "ALICE@example.test",
  "attempts": 1
}
```

### Alternate-route counters · `rate-route`

The login and legacy routes perform the same operation but keep separate counters. Exhausting the current route must not expose a fresh budget on the legacy route.

Legacy and current routes do not share an attempt budget.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
bucket = route + account
```

Repaired logic:

```python
bucket = operation_family + internal_account_id
```

Share an account policy across every endpoint performing the same operation.

Control request:

```json
{
  "account": "alice",
  "route": "login",
  "attempts": 4
}
```

Investigation request:

```json
{
  "account": "alice",
  "route": "legacy",
  "attempts": 1
}
```

### Challenge renewal resets budget · `rate-reset`

Issuing a challenge changes its ID from one to two. A budget bound only to the challenge lifetime can forget the account’s cumulative attempts.

A fresh challenge ID discards the account’s earlier attempts.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
bucket = challenge_id
```

Repaired logic:

```python
bucket = internal_account_id; also_limit_each_challenge()
```

Do not renew the account attempt budget when issuing a challenge.

Control request:

```json
{
  "account": "alice",
  "challenge": "one",
  "attempts": 4
}
```

Investigation request:

```json
{
  "account": "alice",
  "challenge": "two",
  "attempts": 1
}
```

### Fixed-window boundary · `rate-window`

Three attempts at second 59 and three at 60 exceed three per rolling 60 seconds while respecting fixed minute buckets. An explicit lab clock makes the boundary reproducible without waiting.

Three attempts just before a minute boundary and three just after pass within one second.

Exhaust the initial budget separately in each variant, then send the second example. Every credential attempt fails: 401 means verification was reached, while 429 means the limiter blocked it. Never interpret 401 as successful authentication.

Vulnerable logic:

```python
bucket = int(server_time / 60)
```

Repaired logic:

```python
count = attempts_in_last_60_seconds(server_clock)
```

Use a suitable rolling window or token bucket driven by trusted server time.

Control request:

```json
{
  "time": 59,
  "attempts": 3
}
```

Investigation request:

```json
{
  "time": 60,
  "attempts": 3
}
```

## Code-services lab

### SQL search injection · `code-sqli`

Alice’s note search concatenates query into WHERE owner=alice AND note LIKE .... A real in-memory SQLite parser can interpret modified syntax and return Bob’s note without changing the session actor.

Concatenating text into SQL changes the owner predicate.

Tie the result to the violated trust boundary rather than a 200 status. Inspect the resource or rendered value before and after the fix, and distinguish actual parsing from closed transport and policy models.

Vulnerable logic:

```python
sql = "... note LIKE '%" + query + "%'"
```

Repaired logic:

```python
execute("... owner=? AND note LIKE ?", [actor, "%"+query+"%"])
```

Use bound parameters with a session-derived ownership predicate.

Control request:

```json
{
  "query": "Alice"
}
```

Investigation request:

```json
{
  "query": "' OR 1=1 --"
}
```

### NoSQL operator confusion · `code-nosql`

A sign-in API expects a password string. The vulnerable query accepts a $ne comparison object; authentication changes through a type confusion rather than a guessed password.

An object is accepted where a string is required and interpreted as $ne.

Tie the result to the violated trust boundary rather than a 200 status. Inspect the resource or rendered value before and after the fix, and distinguish actual parsing from closed transport and policy models.

Vulnerable logic:

```python
query.password = request.json.password
```

Repaired logic:

```python
require_string(password); compare_secret(password)
```

Validate field types and never pass client operators to a query.

Control request:

```json
{
  "password": "DEMO_VALID_PASSWORD"
}
```

Investigation request:

```json
{
  "password": {
    "$ne": null
  }
}
```

### Template expression evaluation · `code-template`

A preview service mixes input with an evaluated template. The local renderer supports only bounded arithmetic to demonstrate {{7*7}} without eval or system instructions.

A closed {{7*7}} fixture illustrates mixing data with templates; there is no eval.

Tie the result to the violated trust boundary rather than a 200 status. Inspect the resource or rendered value before and after the fix, and distinguish actual parsing from closed transport and policy models.

Vulnerable logic:

```python
render_as_template(user_input)
```

Repaired logic:

```python
render_fixed_template(user_input_as_data)
```

Use a fixed template and pass input only as data.

Control request:

```json
{
  "template": "hello"
}
```

Investigation request:

```json
{
  "template": "{{7*7}}"
}
```

### Unrestricted redirect decision · `code-redirect`

The next return destination comes from a user link. The application assumes it is part of its own flow and accepts an external destination. This case shows the redirect decision without navigating off-device.

The next field accepts an external destination without policy. No external navigation occurs.

Tie the result to the violated trust boundary rather than a 200 status. Inspect the resource or rendered value before and after the fix, and distinguish actual parsing from closed transport and policy models.

Vulnerable logic:

```python
redirect(body.next)
```

Repaired logic:

```python
redirect(allowlisted_local_destination(body.next))
```

Allow specific parsed and normalized local paths.

Control request:

```json
{
  "next": "/welcome"
}
```

Investigation request:

```json
{
  "next": "https://outside.example/"
}
```

### Synthetic internal fetch · `code-ssrf`

A link-preview service has logical access to public.lab and internal.lab. Selecting an internal URL exposes a private configuration resource in the closed transport fixture; no DNS or external network calls occur.

A closed transport fixture exposes an internal response without networking.

Tie the result to the violated trust boundary rather than a 200 status. Inspect the resource or rendered value before and after the fix, and distinguish actual parsing from closed transport and policy models.

Vulnerable logic:

```python
fetch(user_url)
```

Repaired logic:

```python
validate_destination_and_each_redirect(user_url)
```

Enforce destination policy and revalidate every redirect before transport.

Control request:

```json
{
  "url": "https://public.lab/welcome"
}
```

Investigation request:

```json
{
  "url": "http://internal.lab/config"
}
```

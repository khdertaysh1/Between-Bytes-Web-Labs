# Local lesson guide

Run `python app.py`; open **http://127.0.0.1:8000**. Use the Arabic UI selectors (English mode labels included). Reset between comparisons. All data is synthetic and disappears on restart.

## Account enumeration

Select `enumeration`, vulnerable. Submit `alice@example.test` and `nobody@example.test`: observe different HTTP status and message. Fixed returns identical 202/body for both. This lesson simulates the public reset response and queues no mail. Compare the `enumeration` branch of `Labs.run` in `app.py`.

The fix addresses explicit response differences, not measured timing side channels. A real implementation must also review timing, response lengths, headers, redirects and background processing. A generic UI message cannot hide different network responses.

## Rate limiting

Reset; select `rate-limit`, vulnerable. Four requests with an empty X-Forwarded-For yield 401, 401, 401, 429. Change that header to `192.0.2.1`; one more request yields 401. The deliberately broken limiter trusts client-selected identity. There is no real login or correct password in this lesson.

Reset; select fixed. Three requests for the same account are permitted; the fourth is blocked even if X-Forwarded-For changes. Accounts are normalized with strip/casefold. Fixed limits: 3 attempts/account and 6/source per rolling 60 seconds. Source is the socket peer because this server uses no proxy.

Production requires explicit trusted-proxy handling, atomic shared counters, expiration/cleanup, capacity limits and thoughtful account-lockout tradeoffs. This in-memory, single-process demonstration is not a production authentication system; its state maps are reset manually/restart and have no global capacity bound. Identity normalization must match the real application's account policy.

## Repeated reset-email generation

Reset; select `email-flood`, vulnerable. Four requests for Alice create four fake messages. Reset and repeat in fixed mode: only one appears during the first 60 seconds. Fixed also limits requests to 6/source/60 seconds and applies cooldown to unknown account identities. Responses remain generic 202 whether or not a message is queued. After 60 seconds another message can be queued.

Only Alice and Bob at `example.test` can receive fake messages. Mail stays in a 100-item in-memory deque; there is no SMTP transport or valid reset link/token. The outbox is a training observer and must never be exposed publicly in a real application. Real remediation also needs atomic deduplication, bounded delivery queues, global quotas, distributed-abuse monitoring and proper reset-token handling.

## Verification

`python -m unittest discover -s tests -v` runs behavioral tests with a fake clock plus local HTTP integration tests. Requests never target external services. The server binds only to IPv4 loopback and rejects unexpected Host and cross-origin browser POSTs. Do not publish it or expose it through a tunnel.

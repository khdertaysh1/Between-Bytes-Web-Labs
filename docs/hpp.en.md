# HTTP parameter cardinality exercise · 0.12.1

Open Code flaws → Duplicate parameters and parser disagreement (code-hpp). This is the
fourth case in the existing room, not another room or an assigned CVE. All cases stay open.

You are Alice reading local synthetic reports. Edit query_string and send an actual GET
through the fields or HTTP editor. The raw query retains duplicate names and ordering.
The read-only routes are /academy/hpp/vulnerable and /academy/hpp/fixed. A POST/JSON adapter
remains available for existing platform tests and runs the identical parser/policy.

1. Run owner=alice&tag=training against fixed: 200 and Alice’s report.
2. Try owner=bob alone: both variants return 403.
3. Add a second owner after the first. Inspect ordered parameters, validation_owner,
   downstream_owner and records. Does authorization use the same value as lookup?
4. Reverse the order, try an encoded name such as %6fwner, then repeat tag only.
5. Replay the impact-producing query against fixed: duplicate owner returns 400
   ambiguous_owner without any report. Identical owner duplicates are also rejected;
   a single foreign owner returns 403. Repeated tags are a permitted collection.

The HTTP editor accepts only the local HPP GET route and Host, without a request body.
Request history supports manual replay and comparison. Viewing a comparison is not
completion: matching weak impact/fixed rejection plus a valid fixed control are required.
Three hints progress from inspecting the ordered list to reasoning about first/last values.

The actual parser is urllib.parse.parse_qsl. Vulnerable application code deliberately
authorizes the first owner and uses the last for lookup; fixed rejects decoded owner
ambiguity and shares one authorized value. These are explicit local application policies,
not assertions about a real framework/proxy default. There is no external product or
proxy. Synthetic documents are read-only, and rejected operations preserve document state.
Queries are bounded to 1024 encoded ASCII characters/eight fields; malformed encoding,
control characters and unknown fields are rejected. Correct cardinality does not replace
resource ownership checks. Duplicate collection fields are not inherently vulnerabilities.

Primary reference reviewed 2026-10-31: [OWASP WSTG HTTP Parameter Pollution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution/).
The local lesson, implementation and tests are original MIT-licensed work; no upstream
prose/code is copied. Referenced material retains its own copyright/license.

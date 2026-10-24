const EnglishLessons={
  "enumeration": {
    "title": "Account enumeration",
    "short": "Can a password-reset response reveal account membership?",
    "scenario": "Northstar Support: recover your account",
    "body": "You are reviewing a fictional support portal. Compare a known training account with an absent address while keeping the request path and other inputs unchanged.",
    "root": "Membership leaks through the response",
    "cause": "The vulnerable handler changes both status and message based on account existence. The fix returns one public response for both cases.",
    "limits": "This exercise checks explicit status/body differences, not statistical timing resistance or every possible response side channel.",
    "question": "Does one generic UI message fix different HTTP statuses?",
    "answer": "No. The network response can still reveal membership. Check status, body, redirects and timing separately.",
    "steps": [
      "Submit a reset request for alice@example.test and nobody@example.test.",
      "Record the status and message for each vulnerable response.",
      "Repeat both requests in fixed mode and compare the complete public responses."
    ],
    "checks": [
      "Existing account returns 200 in vulnerable mode",
      "Absent account returns 404 in vulnerable mode",
      "Both fixed responses have identical 202 status and body"
    ],
    "hints": [
      "Use the known account first, then the absent address.",
      "Change only the email; keep the endpoint and mode the same."
    ],
    "exam": "Use bob@example.test and visitor@example.test. Demonstrate the vulnerable distinction and matching fixed responses.",
    "sections": [
      [
        "What membership disclosure means",
        "An anonymous visitor learns whether an identifier belongs to an account. The server may need this fact internally, but the recovery response need not reveal it. This is a disclosure of membership, not evidence of password knowledge."
      ],
      [
        "Build a controlled comparison",
        "Use one known synthetic account and one known absent identifier. Compare the same endpoint under the same conditions. A lone 404 is not enough: the difference must correlate with account existence rather than invalid input or a missing route."
      ],
      [
        "Impact and remediation",
        "Membership may support targeted phishing or account discovery; severity depends on context and data sensitivity. Return a consistent public response and review asynchronous processing, timing, length and redirects. Rate limiting reduces abuse but does not erase a per-request disclosure."
      ]
    ],
    "sample": "POST /lab/enumeration/vulnerable\nemail=alice%40example.test\n\nRepeat with an absent account. Compare status and message."
  },
  "rate-limit": {
    "title": "Rate-limit identity bypass",
    "short": "What happens when the limiter trusts a client-selected identity?",
    "scenario": "Northstar Access: three attempts per minute",
    "body": "A fictional login rejects every credential attempt. Reach the limiter, change the forwarded identity, and determine whether the account budget remains enforced.",
    "root": "An untrusted identity became the limiter key",
    "cause": "The vulnerable model trusts X-Forwarded-For directly. Fixed mode uses the normalized account and actual socket peer in this no-proxy deployment.",
    "limits": "There is no correct password or successful login here. Production needs trusted-proxy configuration, atomic shared counters, expiry and account-lockout tradeoffs.",
    "question": "Does a fifth-request 401 mean account takeover?",
    "answer": "No. It means credential evaluation was reached instead of a rate-limit rejection. It proves the modeled limiter bypass only.",
    "steps": [
      "Send four requests with an empty forwarded header.",
      "After 429, change X-Forwarded-For to 192.0.2.1 and send one more.",
      "Repeat in fixed mode; changing the header should not reopen the account budget."
    ],
    "checks": [
      "Observe vulnerable 429 before changing the header",
      "After that rejection, a new header reaches vulnerable 401",
      "Fixed remains 429 after the same identity change"
    ],
    "hints": [
      "Use the same account for four attempts.",
      "After rejection, change only the forwarded header.",
      "401 is invalid credentials; 429 is rate limiting."
    ],
    "exam": "Use bob@example.test. Establish rejection first, then change the header in each mode and capture the difference.",
    "sections": [
      [
        "Define the budget",
        "A limit needs a key, time window and allowance. Three requests per minute is incomplete without saying per account, source or challenge. A weak key may appear effective until its value changes."
      ],
      [
        "Follow the trust boundary",
        "A header supplied by a client is not automatically a trusted network identity. A verified proxy chain is a different deployment. Here no proxy exists, so fixed mode takes the peer address from the socket."
      ],
      [
        "Interpret the evidence",
        "Record the blocked attempt before the identity change. A subsequent 401 shows evaluation resumed, not that authentication succeeded. Real deployments also need shared atomic storage, cleanup and care that account limits do not become an easy lockout mechanism."
      ]
    ],
    "sample": "Requests 1–3: 401\nRequest 4: 429\nRequest 5: same account, changed forwarded header\nCompare vulnerable and fixed."
  },
  "email-flood": {
    "title": "Reset-message abuse",
    "short": "Four accepted requests: how many messages were actually created?",
    "scenario": "Northstar Recovery: one button, repeated mail",
    "body": "The recovery form returns a generic acceptance message. Inspect the in-memory mailbox to distinguish request acceptance from message creation.",
    "root": "Every request creates another message",
    "cause": "Fixed mode adds a per-account cooldown and source budget before queueing a synthetic message, while retaining a generic response.",
    "limits": "Mail never leaves memory. The outbox records creation, not SMTP delivery. Production additionally needs atomic deduplication, bounded queues and global quotas.",
    "question": "Do four 202 responses prove four delivered emails?",
    "answer": "No. Acceptance, queueing and delivery are separate events. This lab observes synthetic message creation only.",
    "steps": [
      "Send four requests for the same training account in vulnerable mode.",
      "Count the created messages in the evidence.",
      "Repeat in fixed mode within 60 seconds and compare creation counts."
    ],
    "checks": [
      "Four vulnerable messages were created",
      "Four fixed requests were submitted",
      "Only one fixed message was created during the cooldown"
    ],
    "hints": [
      "Use alice@example.test four times in each mode.",
      "Read mail_count rather than inferring delivery from HTTP 202."
    ],
    "exam": "Use bob@example.test. Submit four requests per mode during the minute and record message creation counts.",
    "sections": [
      [
        "Acceptance is not delivery",
        "A recovery workflow may accept a request, create a message, queue it and then deliver it. These are different stages. Repeated message creation can cause nuisance and cost without any account takeover."
      ],
      [
        "Measure the side effect",
        "Start an empty round and use one synthetic recipient. Compare four requests in each mode. The training mailbox contains at most 100 messages and never sends externally; it is an observer, not a public account feature."
      ],
      [
        "Apply the right control",
        "A generic response prevents an explicit enumeration leak but does not prevent repeated queueing. Use cooldown and source budgets before message creation, atomic deduplication and delivery quotas. Concurrent workers need a shared, race-safe implementation."
      ]
    ],
    "sample": "Four recovery requests\nvulnerable: mail_count=4\nfixed: mail_count=1\nAll responses may still be 202."
  },
  "idor": {
    "title": "Object-level authorization",
    "short": "Change an invoice reference: does the server check who owns it?",
    "scenario": "Northstar Shop: your invoice and someone else’s",
    "body": "The server fixes the synthetic actor to Alice. Read her invoice, then change only the resource reference to Bob’s invoice and test the same operation after the fix.",
    "root": "The object lookup omits authorization",
    "cause": "The vulnerable handler returns an invoice by ID alone. The fix compares its owner with the server-defined actor.",
    "limits": "Alice is a fixed training identity, not a real login. Production must enforce resource, operation, role and tenant policies. Random identifiers are not authorization.",
    "question": "Does changing numeric IDs to UUIDs fix this?",
    "answer": "No. Hard-to-guess references still require a server-side access decision whenever they are used.",
    "steps": [
      "Read Alice’s invoice 1001.",
      "Change resource to 1002 while the actor remains Alice.",
      "In fixed mode, verify that Bob’s invoice is denied and Alice’s remains readable."
    ],
    "checks": [
      "Read Alice’s vulnerable invoice",
      "Read Bob’s vulnerable invoice as Alice",
      "Fixed denies Bob’s invoice",
      "Fixed still permits Alice’s invoice"
    ],
    "hints": [
      "Begin with 1001 and inspect owner.",
      "Change only the reference to 1002.",
      "Test both allowed and denied cases after the fix."
    ],
    "exam": "Use invoices 2001 for Alice and 2002 for Bob. Capture both allowed and denied cases without changing the actor.",
    "sections": [
      [
        "Identity and permission differ",
        "Authentication identifies a requester; authorization decides whether that identity may perform an operation on a resource. Recognizing Alice does not authorize every invoice."
      ],
      [
        "Look for the actual disclosure",
        "References can appear in a path, query or body. Editing an ID alone is not a vulnerability: receiving another owner’s restricted data is the evidence. Capture actor, owner and relevant synthetic content."
      ],
      [
        "Test the permission matrix",
        "A fix that denies all invoices breaks the intended feature. Check that it denies Bob’s resource while retaining Alice’s access. Unpredictable IDs reduce guessing but do not replace an access check."
      ]
    ],
    "sample": "actor=alice (server-defined)\nresource=1001: owner=alice\nresource=1002: owner=bob\nFixed must distinguish ownership."
  },
  "edge403": {
    "title": "Edge and origin authorization",
    "short": "Does the origin enforce access when the gateway already blocks?",
    "scenario": "Northstar Admin: a protected gateway, an unprotected origin",
    "body": "Choose between two local code branches named edge and origin. The requester is anonymous. This is an authorization model, not a live proxy service or Cloudflare bypass.",
    "root": "Only the edge branch checks access",
    "cause": "The vulnerable origin branch forgets authorization. Fixed mode denies the anonymous visitor in both branches.",
    "limits": "Both branches run in one local process. No origin discovery, WAF evasion or real Cloudflare challenge is implemented.",
    "question": "Does a real 403 identify its issuing layer or imply a bypass?",
    "answer": "No. Correlate responses with your server logs and configuration before identifying a cause or access failure.",
    "steps": [
      "Request the vulnerable edge branch and observe 403.",
      "Request its origin branch and inspect the synthetic admin resource.",
      "Repeat both in fixed mode; both must deny the anonymous actor."
    ],
    "checks": [
      "Vulnerable edge denies access",
      "Vulnerable origin reveals the synthetic admin resource",
      "Fixed edge denies access",
      "Fixed origin denies access"
    ],
    "hints": [
      "layer selects a local branch, not a network destination.",
      "Compare edge and origin under the same mode."
    ],
    "exam": "Record both branches in both modes, including the resource exposed by the vulnerable origin.",
    "sections": [
      [
        "A status is not a root cause",
        "403 reports a denial, not which infrastructure component made the decision. Application rules, proxies and other controls may produce it."
      ],
      [
        "Enforce application permission",
        "Gateway controls do not replace origin authorization. In this model an anonymous visitor reaches a synthetic admin resource through one branch, despite being rejected by another."
      ],
      [
        "Respect the scope",
        "Compare the same visitor and resource across branches, then confirm both deny after the fix. These branches do not reproduce a commercial WAF, real network routes or browser challenges."
      ]
    ],
    "sample": "anonymous actor\nedge/vulnerable: 403\norigin/vulnerable: synthetic admin resource\nboth fixed branches: 403"
  },
  "reflected-xss": {
    "title": "Reflected cross-site scripting",
    "short": "Trace a search input from the server response to browser execution.",
    "scenario": "Northstar Search: text or executable markup?",
    "body": "Submit a search phrase to the local server. The vulnerable response places it inside HTML; fixed mode encodes the HTML text context. Execution is observed in an opaque-origin sandbox.",
    "root": "Untrusted input enters an HTML context",
    "cause": "Raw HTML interpolation allows element/event interpretation. Fixed mode uses html.escape for this specific text context.",
    "limits": "The preview deliberately enables inline scripting within its isolated origin. The 650ms signal window is not proof against delayed execution, other sinks or every XSS vector.",
    "question": "Does a bold b element prove JavaScript execution?",
    "answer": "No. It demonstrates HTML interpretation only. The required alert marker demonstrates execution within this training frame.",
    "steps": [
      "Try a plain search and then simple HTML.",
      "Type input that invokes alert(\"BB-LAB\") inside the vulnerable preview.",
      "Repeat exactly the same input in fixed mode and confirm literal rendering."
    ],
    "checks": [
      "Observe the required vulnerable execution marker",
      "Same input renders literally in fixed mode without the observed marker"
    ],
    "hints": [
      "Start with <b>hello</b>; that is not JavaScript execution.",
      "Think about an error event on an invalid image.",
      "Local example: <img src=x onerror=\"alert('BB-LAB')\">"
    ],
    "exam": "Produce alert(\"BB-EXAM\") in the vulnerable frame, then show the same input as literal text in fixed mode.",
    "sections": [
      [
        "Reflection is not execution",
        "A value can appear in a response safely. Its insertion context and interpretation determine whether it becomes markup or code. First establish where the value is placed."
      ],
      [
        "Prove the browser behavior",
        "A formatting tag demonstrates HTML interpretation. This frame replaces alert with a visible training signal; use the correct round marker. The parent checks the frame identity and round token."
      ],
      [
        "Use context-appropriate output",
        "html.escape is appropriate for this HTML text example, not a universal JavaScript, CSS or URL sanitizer. Compare the same input after the fix, and describe the limited observation interval rather than declaring every payload safe."
      ]
    ],
    "sample": "Local GET query → server response\nVulnerable: raw HTML text-context insertion\nFixed: encoded literal text\nReflection alone is not XSS execution."
  },
  "dom-xss": {
    "title": "DOM-based cross-site scripting",
    "short": "Follow a browser message into innerHTML without sending the payload to the server.",
    "scenario": "Northstar Preview: a client-side rendering mistake",
    "body": "The workspace sends your text to the isolated preview with postMessage. The vulnerable frame writes it with innerHTML; the fixed frame uses textContent.",
    "root": "The DOM sink interprets data as HTML",
    "cause": "Checking the sender of a message does not make its content safe for HTML interpretation. The fix changes the sink to textContent.",
    "limits": "The source is postMessage in this lab, not a URL query. The payload stays in the browser. If an application requires HTML, a carefully chosen sanitizer and policy may be needed.",
    "question": "Can XSS exist when the payload is absent from the server response?",
    "answer": "Yes. A client-side source can flow directly into an unsafe DOM sink after the initial response has loaded.",
    "steps": [
      "Compare plain text and a formatting element.",
      "Create the required BB-LAB alert marker through a DOM event.",
      "Repeat the same input using the fixed textContent sink."
    ],
    "checks": [
      "Observe vulnerable DOM execution",
      "Same input renders as fixed literal text without the observed marker"
    ],
    "hints": [
      "Inspect the source-to-sink flow, not only the server response.",
      "script inserted through innerHTML normally does not execute; event handlers can still matter.",
      "Local example: <img src=x onerror=\"alert('BB-LAB')\">"
    ],
    "exam": "Produce alert(\"BB-EXAM\") through the browser message source and verify literal rendering after the sink fix.",
    "sections": [
      [
        "Map source to sink",
        "Track attacker-influenced data to the operation that interprets it. This lab uses a parent message source and innerHTML sink. Other applications may use URLs, stored values or API responses."
      ],
      [
        "Sender checks and content handling differ",
        "The preview verifies its parent and round token before accepting a message. That controls the message channel but does not encode its value for HTML."
      ],
      [
        "Choose a suitable sink",
        "textContent represents text without parsing elements. Failure of an inserted script tag to execute does not establish that innerHTML is safe. Record the execution marker and compare the exact input after the fix."
      ]
    ],
    "sample": "Parent postMessage({value})\nFrame event.data.value → innerHTML or textContent\nPayload does not travel to the HTTP server."
  },
  "csrf": {
    "title": "Cross-origin request forgery",
    "short": "Can another local origin change synthetic account state using its session?",
    "scenario": "Northstar Profile: a request you did not intend",
    "body": "A second loopback origin sends a simple credentialed POST. Inspect the account note and revision before and after, because that origin cannot read its opaque response.",
    "root": "A valid cookie is mistaken for user intent",
    "cause": "The vulnerable endpoint changes the synthetic note with a session cookie alone. Fixed mode checks the actual Origin and a session-bound CSRF token.",
    "limits": "Different loopback ports are cross-origin but same-site. This is not a SameSite bypass across real sites. Only synthetic account state is changed.",
    "question": "Does inability to read a response prove no action occurred?",
    "answer": "No. A request can change state while the browser prevents its sender from reading the response.",
    "steps": [
      "Send a new note from the second origin to vulnerable mode.",
      "Repeat against fixed mode and confirm that its revision remains unchanged.",
      "Use the legitimate same-origin request and confirm the fixed feature still works."
    ],
    "checks": [
      "Second origin changes vulnerable state",
      "Fixed state does not change from the second origin",
      "A legitimate fixed write succeeds"
    ],
    "hints": [
      "Use training-csrf as a note and select the second origin.",
      "Compare before.revision and after.revision.",
      "Finish with a legitimate fixed write."
    ],
    "exam": "Use exam-csrf. Prove the unwanted vulnerable write, rejected fixed write and legitimate fixed write.",
    "sections": [
      [
        "Identify the trust boundary",
        "Browsers may attach session cookies automatically. A valid session alone does not establish that its user intended a state-changing action. CSRF does not require stealing the cookie."
      ],
      [
        "Observe the side effect",
        "The second origin sends a simple no-cors request and cannot inspect the response. The account workspace independently checks note and revision. A missing token in markup or a status alone is insufficient evidence of a successful state change."
      ],
      [
        "Fix and test both paths",
        "The fix combines same-origin validation with a session-bound token. Test the rejection and the legitimate write. SameSite and Fetch Metadata may add defenses, but the same-site two-port setup here does not measure real cross-site cookie behavior."
      ]
    ],
    "sample": "Second origin → credentialed POST\nResponse is opaque to that page\nAccount workspace checks note/revision afterward"
  },
  "cors": {
    "title": "Credentialed cross-origin reading",
    "short": "Prove browser readability of synthetic private data, not just a reflected header.",
    "scenario": "Northstar Account API: who may read the response?",
    "body": "A second local origin makes a credentialed fetch for synthetic private data. Compare browser-readable vulnerable output with the fixed origin policy.",
    "root": "An untrusted origin is granted response access",
    "cause": "Reflecting arbitrary Origin with credentials allows this page to read session-bound data. Fixed mode does not grant its origin permission.",
    "limits": "The origins differ by loopback port but are same-site. CORS is not server authorization. Fetch failure alone can have other causes, so compare legitimate reads and policy tests.",
    "question": "Does wildcard ACAO on public data prove account-data theft?",
    "answer": "No. Determine data sensitivity, credentials and actual browser readability. A wildcard is not the same as a valid credentialed-read permission.",
    "steps": [
      "Read from the second origin in vulnerable mode.",
      "Repeat in fixed mode and observe that the browser withholds the response.",
      "Confirm that legitimate fixed same-origin reading still works."
    ],
    "checks": [
      "Second origin reads vulnerable private data",
      "Browser blocks the second-origin fixed read",
      "Legitimate fixed reading remains available"
    ],
    "hints": [
      "Inspect readable and body in the evidence.",
      "The server may return 200 even when JavaScript cannot read it.",
      "Compare a legitimate fixed read before concluding a network error."
    ],
    "exam": "Capture the credentialed second-origin read, fixed browser denial, and successful legitimate read.",
    "sections": [
      [
        "What the browser enforces",
        "CORS governs whether script in one origin may read another origin’s response. A port change changes origin. It does not replace authentication or authorize arbitrary non-browser HTTP clients."
      ],
      [
        "From header to impact",
        "A reflected origin is not always a vulnerability: the data may be public or the credential rules may prevent reading. Show private synthetic content reaching JavaScript in the second page."
      ],
      [
        "Reading and sending are distinct",
        "A browser may send simple requests without exposing their response. That is why CORS alone is not CSRF prevention. This exercise reads an authenticated fixture; the fixed response may still be 200 without cross-origin permission."
      ]
    ],
    "sample": "Origin B: fetch(originA, {credentials:\"include\"})\nDoes JavaScript in B receive the private body?"
  },
  "open-redirect": {
    "title": "Untrusted redirect destinations",
    "short": "Edit a return destination and inspect the redirect policy decision.",
    "scenario": "Northstar Checkout: where does Continue lead?",
    "body": "The next parameter supplies a destination. Inspect the policy decision and proposed Location without navigating to an external service.",
    "root": "An untrusted return address controls navigation",
    "cause": "The vulnerable model accepts the supplied destination. Fixed mode accepts only explicitly allowed local routes.",
    "limits": "This is a JSON decision preview, not an actual 302 response or external browser navigation. It does not demonstrate token theft or an authentication bypass.",
    "question": "Is every string beginning with a slash a safe local route?",
    "answer": "No. Protocol-relative //host values have different semantics. An explicit route list avoids that weak prefix check here.",
    "steps": [
      "Test /welcome as a permitted route.",
      "Compare https://outside.example/landing in both modes.",
      "Confirm that the fixed local route still works."
    ],
    "checks": [
      "Vulnerable local destination accepted",
      "Vulnerable external destination accepted",
      "Fixed rejects the external destination",
      "Fixed permits the local destination"
    ],
    "hints": [
      "Try one allowed route and one outside.example address.",
      "Read location, external and would_status."
    ],
    "exam": "Use /account and https://outside.example/exam, and record both decisions in both modes.",
    "sections": [
      [
        "Define the actual behavior",
        "Returning a URL as text is not the same as redirecting. This fixture reports a proposed decision explicitly; it never sends an external Location header or follows a URL."
      ],
      [
        "Describe impact carefully",
        "An actual untrusted redirect can support phishing or confusing trusted links. Token leakage or login bypass requires additional conditions and separate evidence."
      ],
      [
        "Validate the intended destination",
        "Fixed mode accepts /welcome and /account exactly. It rejects protocol-relative values, other routes and control characters. A product needing complete URLs requires a policy appropriate to its parser and workflow."
      ]
    ],
    "sample": "next=/welcome → allowed local decision\nnext=https://outside.example/landing → external decision\nNo external navigation occurs."
  },
  "ssrf": {
    "title": "Server-side fetch destinations",
    "short": "Follow public, private and redirected destinations in a closed transport model.",
    "scenario": "Northstar Link Preview: the server fetches a URL",
    "body": "A deterministic transport provides public.lab and internal.lab fixtures. There is no DNS resolution, network connection or local-file access.",
    "root": "User input controls a privileged server-side destination",
    "cause": "The vulnerable model permits an internal destination and follows a redirect to it. Fixed mode rejects both before following while retaining the public resource.",
    "limits": "Synthetic transport only: this does not test real address parsing, rebinding, metadata access or egress. Production needs destination resolution checks and network controls.",
    "question": "Is checking the first URL enough when redirects are followed?",
    "answer": "No. Validate the next destination before connecting, or disable following when the workflow does not need it.",
    "steps": [
      "Fetch http://public.lab/welcome as the public baseline.",
      "Compare internal.lab/config and public.lab/redirect in vulnerable mode.",
      "Repeat both in fixed mode, then confirm public access remains."
    ],
    "checks": [
      "Vulnerable private fixture returned",
      "Vulnerable redirect reaches the private fixture",
      "Fixed rejects both private and redirected destinations",
      "Fixed public fixture remains available"
    ],
    "hints": [
      "Only the three documented fixture URLs exist.",
      "Inspect private and redirect_followed."
    ],
    "exam": "Prove direct and redirected private output in vulnerable mode, both rejections in fixed mode, and fixed public access.",
    "sections": [
      [
        "Understand the requester",
        "SSRF concerns a server-side operation directed by an untrusted input. The server’s access position may differ from the user’s. Displaying a URL in a browser is not evidence of a server fetch."
      ],
      [
        "Interpret this model",
        "private:true and DEMO_INTERNAL_CONFIG identify a synthetic internal response. They prove model behavior, not a real internal connection or secret extraction. Arbitrary real addresses are refused."
      ],
      [
        "Validate each connection",
        "The next redirect destination matters as much as the initial one. Real deployments need resolved-address checks before connections, controlled egress and bounded time/size; a hostname string comparison alone is not a comprehensive SSRF defense."
      ]
    ],
    "sample": "public.lab/welcome: public fixture\ninternal.lab/config: private fixture\npublic.lab/redirect: modeled internal redirect"
  },
  "api-keys": {
    "title": "Secrets in frontend assets",
    "short": "Distinguish an intentionally public key from a server secret in a bundle.",
    "scenario": "Northstar Billing: inspect the published assets",
    "body": "Use the fixture browser to inspect JavaScript containing a publishable demo key and an intentionally invalid server secret. No provider is contacted.",
    "root": "A server-only secret was shipped to the browser",
    "cause": "Anyone receiving frontend assets can inspect their contents. Fixed mode removes the synthetic server secret while preserving the intended public key.",
    "limits": "All values are invalid demo strings. A key-like name or regex match is not enough to establish sensitivity, usable privileges or actual compromise.",
    "question": "Is every API key appearing in JavaScript a vulnerability?",
    "answer": "No. Some keys are designed for public clients. Determine their documented purpose, restrictions and permissions before asserting exposure of a secret.",
    "steps": [
      "Inspect /robots.txt for fixture assets.",
      "Read /assets/checkout.js and classify PUBLIC_KEY versus SERVER_API_SECRET.",
      "Verify that fixed mode removes the secret but retains the public key."
    ],
    "checks": [
      "Locate the synthetic server secret in the vulnerable asset",
      "Fixed asset retains the public key without the server secret"
    ],
    "hints": [
      "The resource index names the JavaScript fixtures.",
      "Do not treat every KEY field as a secret."
    ],
    "exam": "Inspect /assets/billing.js in both modes and verify the intended public/private distinction.",
    "sections": [
      [
        "Names are not permissions",
        "A value called key can be public, and a secret can have an ordinary name. Classify it by intended use and permissions, not pattern shape alone."
      ],
      [
        "Collect minimal evidence",
        "The fixture contains DEMO_ONLY values that cannot authenticate anywhere. There is no key-validation feature or external provider access. In authorized research, avoid spreading real secrets in public reports or logs."
      ],
      [
        "Removal is not revocation",
        "Deleting a real secret from a new bundle does not invalidate copies of the old one. Production response may require rotation, permission review and audit. This exercise checks removal from the fixture only."
      ]
    ],
    "sample": "PUBLIC_KEY=\"demo_publishable_ui\"\nSERVER_API_SECRET=\"DEMO_ONLY_NOT_A_VALID_API_SECRET\"\nBoth are synthetic, nonfunctional values."
  },
  "exposed-files": {
    "title": "Exposed configuration and backup files",
    "short": "Follow a resource index to a synthetic configuration file published by mistake.",
    "scenario": "Northstar Deploy: a backup entered the public build",
    "body": "The fixture browser reads a closed in-memory dictionary, never your device’s files. Use index hints to locate a backup and verify that the fixed public build excludes it.",
    "root": "Operational material was published as public content",
    "cause": "The vulnerable fixture serves synthetic config/backup content. Fixed mode refuses private fixtures even when their exact path is known.",
    "limits": "No filesystem traversal, host-file access or Internet scanning exists. File names alone do not establish sensitivity; inspect actual content and access.",
    "question": "Does putting a private path in robots.txt protect it?",
    "answer": "No. robots.txt is crawler guidance, not authorization. It can reveal path names and cannot enforce access to a resource.",
    "steps": [
      "Read /robots.txt and note backup paths.",
      "Inspect /.env.backup in vulnerable mode.",
      "Verify fixed refusal, then confirm /public/readme.txt stays public."
    ],
    "checks": [
      "Inspect the public resource index",
      "Read the synthetic private config in vulnerable mode",
      "Fixed refuses the same private file",
      "Fixed public document remains readable"
    ],
    "hints": [
      "Begin with /robots.txt.",
      "Inspect the DEMO_FAKE fields in /.env.backup.",
      "Check a public file after confirming the private refusal."
    ],
    "exam": "Use /robots.txt, then /backups/settings.env. Prove its vulnerable disclosure and fixed refusal while preserving the public readme.",
    "sections": [
      [
        "How exposure happens",
        "Deployment trees may accidentally include environment files, editor backups or version-control metadata. Even non-secret content can reveal structure, but classify actual sensitivity rather than calling every published detail a security issue."
      ],
      [
        "Inspect content, not only status",
        "A generic HTML error returning 200 does not prove a file exists. Read the fixture body and correlate it with the selected path. Unknown and refused private resources both return 404 here."
      ],
      [
        "Fix the deployment boundary",
        "Publish only intended public build artifacts and keep operational config elsewhere. Renaming a file or hiding an index does not correct an overly broad serving rule. Previously leaked real secrets may require separate revocation."
      ]
    ],
    "sample": "/robots.txt → discovery hints only\n/.env.backup → vulnerable fixture content\nFixed: 404 without private content"
  }
};

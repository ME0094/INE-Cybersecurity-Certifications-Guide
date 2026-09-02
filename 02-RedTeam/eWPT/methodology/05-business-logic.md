# eWPT Methodology — Phase 05: Business Logic Testing

> Web Application Penetration Testing · INE-Cybersecurity-Certifications-Guide

Business logic flaws are not classic injection bugs — they are violations of the rules the application is *supposed* to enforce: prices, quotas, steps, states, and workflows. The application behaves exactly as programmed, and that programmed behavior is wrong. Finding these requires reasoning about intended versus unintended behavior, which makes them the most creative and the most often-missed part of a web test. All testing happens in authorized environments; never manipulate real payments, inventory, or other people's data without explicit scope.

## How to Reason About Intended vs Unintended Behavior

Before sending a single tampered request, write down the business rules:

1. Read the product: what is this app for, who uses it, what money/data moves?
2. Enumerate each critical workflow end to end (checkout, transfer, booking, signup) and note the *assumed* order and constraints.
3. For every step ask: **what invariant must hold?** (total = sum of items; one account per email; discount once per order; stock cannot go negative).
4. Then attack the invariants: reorder steps, repeat steps, skip steps, mutate values between steps, and race parallel requests.

> Mindset: the developer coded the happy path and trusted the client for the rest. Your job is to find every path the developer did not imagine.

## Workflow Bypass

Workflows enforce order (pay before download, verify before activation, admin-approve before publish). Bypasses come from jumping steps or replaying earlier steps at the wrong time.

```text
# Checkout-style flow to examine
# Step 1: POST /cart/add
# Step 2: POST /checkout/address
# Step 3: POST /checkout/payment        <- payment confirmation happens here
# Step 4: GET  /order/confirm/{id}      <- normally only reachable after Step 3

# Bypass test A — forced browsing to the final step
GET /order/confirm/58231            # does it work without paying?

# Bypass test B — mark the step complete yourself
POST /checkout/payment  {"paid": true}   # client-declared state
POST /checkout/payment  {"transactionId": "anything"}  # unverified reference

# Bypass test C — skip an intermediate step entirely
POST /checkout/payment (straight after /cart/add, no address step)
```

For each step, compare the response against the legitimate sequence and look for "state progression" cookies or hidden fields the client carries between steps — tamper with those too.

## Price and Quantity Manipulation

The application must compute money and quantities server-side from authoritative data. When the client supplies them, tampering is trivial.

```bash
# Every one of these is worth a try in an authorized shop lab:
# 1. Negative quantity on an item -> total decreases
curl -s -X POST https://app.example.com/cart/add -d 'itemId=10&qty=-5'
# 2. Negative price on a line item
curl -s -X POST https://app.example.com/cart/update -d 'itemId=10&price=-100.00'
# 3. Price override on add-to-cart (classic: client sends the price)
curl -s -X POST https://app.example.com/cart/add \
     -H 'Content-Type: application/json' \
     -d '{"itemId":10,"price":0.01,"qty":1}'
# 4. Quantity overflow / huge numbers: qty=999999999 may overflow integer math
# 5. Coupon abuse: apply the same coupon many times, or one that is not yours
curl -s -X POST https://app.example.com/cart/coupon -d 'code=WELCOME10'
curl -s -X POST https://app.example.com/cart/coupon -d 'code=WELCOME10'   # twice?
# 6. Currency/rounding: unit prices with many decimals can round against the business
```

Watch for two layers: what the browser shows (cosmetic) and what the API accepts (authoritative). If the API validates totals, try changing the *items* while keeping the total fixed (quantity change after a server-computed total), or add a second identical item to exploit per-item discount caps.

## Race Conditions

Race conditions (TOCTOU — time-of-check to time-of-use) exploit the window between a server's *check* and its *use* of a resource. Classic victims: coupon redemption, wallet balance spend, stock deduction, and one-time signup bonuses.

```bash
# Parallel requests on the same resource (authorized lab)
# The idea: N simultaneous redemptions of a single-use coupon/balance.

# 1. Capture the redeem request in Burp Repeater.
# 2. Send it with many concurrent threads (Burp "Send group in parallel" or:
#    for i in $(seq 1 20); do
#      curl -s -X POST https://app.example.com/redeem \
#           -d 'code=SINGLEUSE-123' -b 'session=MYCOOKIE' &
#    done; wait
# 3. Count successes. Two or more 200s = the single-use invariant broke.
```

Modern approaches also test *race windows* (e.g. "last-item" stock with delayed decrement) and multi-endpoint races (add item and remove item racing the stock check). A clean lab methodology: use Burp's Turbo Intruder or a small concurrent loop, keep the request count modest, and verify the invariant (balance, stock, coupon count) server-side afterwards.

## Integer and Order Issues

Subtle arithmetic and sequencing flaws often hide in plain sight.

- **Integer overflow/underflow:** manipulating a quantity, balance, or order ID beyond its type's bounds wraps the value (e.g. `2147483647 + 1` becoming negative). Try huge and negative boundary values on every numeric field.
- **Order of operations abuse:** shipping cost computed before a discount is applied vs after; tax on discounted price — try coupon + free-shipping combinations where the *sequence* of server rules produces a total below zero.
- **Rounding:** per-line rounding that differs from total rounding can shave fractions per transaction — tiny per order, significant at scale.
- **Order ID / sequence predictability** (ties into Phase 03): guessable incrementing IDs let you enumerate other orders.

```text
# Boundary probes to run on numeric fields (lab)
qty=1, qty=0, qty=-1, qty=2147483647, qty=2147483648, qty=99999999999999
price=0, price=0.001, price=-0.01
# Watch server responses for validation errors vs silent acceptance —
# silent acceptance of negatives or overflows is the finding.
```

## CAPTCHA and Step Reuse

CAPTCHAs and per-step tokens are meant to prove human, one-time, in-order behavior. Test whether they can be reused or skipped:

```text
# CAPTCHA bypass tests
# 1. Reuse: submit a solved CAPTCHA token twice — does the second request pass?
# 2. Skip: omit the captcha field entirely, or send an empty value.
# 3. Weak validation: is the CAPTCHA answer checked server-side at all,
#    or only client-side? (View-source and API inspection answer this.)
# 4. Automated solvers exist for weak CAPTCHAs — note the finding, but
#    demonstrate with repeated reuse rather than heavy solving.

# Step-token reuse: complete step 1 (gets token T), then replay step-1
# requests with T while also advancing to step 2. If T stays valid for
# repeated actions, the "one-time" property is broken.
```

## State Machine Flaws

Stateful workflows (orders, verifications, approvals, account lifecycle) should only allow legal transitions: `pending -> paid -> shipped`, never `pending -> shipped` or `shipped -> pending`. Map the state machine, then attack the edges.

```text
# States and the transitions to probe
# Draft -> Submitted -> Under Review -> Approved -> Published
# Illegal moves to test:
#   Submitted -> Published          (skip review)
#   Approved -> Draft               (roll back a decision)
#   Published -> Draft -> Approved  (re-publish content that was rejected)

# How to probe: identify the state-changing parameter (often "status", "action",
# "state" in the request body or a hidden field) and set it directly:
POST /api/article/58231  {"status":"published"}    # as a submitter, not an admin
POST /api/order/90210    {"state":"completed"}     # before payment cleared
```

Direct state manipulation overlaps with access control (Phase 03) — the difference is that here the *workflow rules* are violated even by a legitimate user of the right privilege level.

## Common Mistakes & Tips

- **Tampering with the UI only.** The browser hides the real API. Intercept traffic, find the JSON/API calls, and tamper there; UI fields like a displayed total are cosmetic.
- **Forgetting to check the server response.** Client-side totals that the server recalculates are not findings — always verify with the authoritative response and a second view (admin panel, order history).
- **One-and-done testing.** Business logic flaws need baselines: perform the legitimate flow first, record normal responses, then tamper and diff. Skipping the baseline produces false positives.
- **Racing without control.** Concurrency tests without a known invariant ("this coupon is single-use", "balance = 100") prove nothing. State the invariant, then try to break it.
- **Ignoring the "why".** A finding needs impact: a negative-priced cart is only critical if the checkout accepts it end to end. Prove the full chain up to the point your scope allows.
- **Missing multi-step replay.** Single-step tests miss flaws that only appear when you replay step 1 after completing step 3, or jump 1→4.
- **Not reading the product.** You cannot find business logic flaws you do not understand. Read the help docs, FAQ, and terms — they describe the intended rules you will violate.

## Checklist / Self-Test

- [ ] I documented the intended workflow and its invariants for each critical business function.
- [ ] I attempted forced browsing to late workflow steps (e.g. confirm without paying).
- [ ] I tampered with prices, quantities, and totals at the API layer, not the UI layer.
- [ ] I tested negative, zero, overflow, and extreme values on numeric fields.
- [ ] I raced single-use actions (coupons, balances, stock) with parallel requests and verified server-side state.
- [ ] I tested CAPTCHA and step-token reuse/skipping.
- [ ] I mapped the state machine and tried illegal transitions via direct state parameters.
- [ ] Every finding has a legitimate-flow baseline proving the behavior is unintended.

## Further Resources

- OWASP Top 10 — A04 Insecure Design, which frames business logic as a design-level risk: https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — WSTG-BUSL (Business Logic Testing) chapter with workflow, price, race, and state tests: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — "Business logic vulnerabilities" topic with labs covering excessive trust, flawed workflows, and race conditions: https://portswigger.net/web-security

# eWPT Methodology — Phase 03: Authorization Testing

> Web Application Penetration Testing · INE-Cybersecurity-Certifications-Guide

Authorization answers "what are you allowed to do?" Authentication proves who you are; authorization decides which resources and actions you may reach. Broken access control is consistently at the top of the OWASP Top 10 because it is common, easy to miss, and usually easy to exploit. The testing model: obtain two or more accounts with different privilege levels (user/admin, tenant A/tenant B) and compare what each can actually do. Authorized lab environments only.

## Broken Access Control — The Model

Access control flaws happen when the server trusts something the client declares, or when a check exists in the UI but not in the API.

- **Object-level** authorization: can user A read/change user B's object?
- **Function-level** authorization: can a regular user invoke an admin function?
- **Vertical** escalation: lower privilege → higher privilege.
- **Horizontal** escalation: same privilege, different identity/tenant/object.

Core habits for this phase:

1. Enumerate every function and resource the app offers (Phase 01 inventory pays off here).
2. Determine which privilege level each function *should* require.
3. Try each function with every account level you control.
4. Try direct navigation to URLs/APIs you were never shown in the UI.

## IDOR and Insecure Object References

IDOR (Insecure Direct Object Reference) means the application exposes a direct reference to an internal object — an ID, filename, account number — and fails to verify the requester owns it.

Classic shapes:

```text
GET /account/1001                -> profile of user 1001
GET /invoice?id=5823             -> another tenant's invoice
GET /download?file=report_2024.pdf -> any file, if path is user-controlled
POST /api/profile/update/1001    -> edit someone else's profile
```

Test sequence:

```bash
# 1. Fetch your own resource and note the response.
curl -s https://app.example.com/account/1001 -b 'session=MYCOOKIE'

# 2. Replace the reference with a neighbor/other value and compare.
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/account/1000 -b 'session=MYCOOKIE'
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/account/1002 -b 'session=MYCOOKIE'

# 3. If IDs look numeric, step through a small range automatically.
for id in $(seq 990 1010); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://app.example.com/account/$id" -b 'session=MYCOOKIE')
  echo "$id -> $code"
done
```

When testing, mutate **one variable at a time** and compare against your own baseline: status code, body length, and content. A 200 with different content is proof of broken object-level authorization. If you cannot use a second account, a second object of your own (create two invoices, two notes) proves the same flaw legally.

Also look for object references hidden in less obvious places:

- `POST /api/transfer` with a `fromAccount` you do not own.
- `PUT /api/order` where the JSON includes `"userId": 1001`.
- GUIDs or hashes that look random — test them anyway (some are sequential UUIDv1 or base64 of an integer).
- Filenames: `?file=..%2F..%2Fetc%2Fpasswd` is a traversal issue (Phase 04) but `?file=other_users_doc.pdf` is an IDOR.

## Horizontal Privilege Escalation

Horizontal escalation = accessing resources at your own privilege level that belong to someone else.

```bash
# Two test accounts, alice and bob, both normal users.
# Log in as alice, capture alice's session cookie, and hit bob's resource:
curl -s https://app.example.com/messages/58231 -b 'session=ALICE_COOKIE'
# Compare with bob's view; identical content = horizontal IDOR

# JSON API flavor: the object id sits in the body, not the URL
curl -s -X POST https://app.example.com/api/order/view \
  -H 'Content-Type: application/json' -b 'session=ALICE_COOKIE' \
  -d '{"orderId": 777001}'
```

Always confirm impact, not just access: can Alice *modify* Bob's message, or only read it? Read is information disclosure; write is full integrity loss. The severity escalates when you can change the object (delete, edit, transfer).

## Vertical Privilege Escalation

Vertical escalation = a low-privilege account reaches high-privilege functions or data.

Where checks live and fail:

- **UI-only hiding:** the admin menu is hidden from normal users, but `/admin/users` answers 200 for them anyway.
- **Client-side role claims:** the role travels in a cookie, header, or JWT claim the client controls (`role: user` → `role: admin`).
- **Predictable admin routes:** `/admin`, `/api/admin`, `/backoffice` found during content discovery.
- **Insecure direct function calls:** a normal user calls the endpoint that deletes users, or that changes another user's role.

```bash
# Direct navigation (forced browsing) to a function-level resource
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/admin/users -b 'session=NORMAL_USER'
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/api/admin/users -b 'session=NORMAL_USER'

# Method confusion: the UI uses GET /admin, does POST /admin behave differently?
curl -s -X POST -o /dev/null -w '%{http_code}\n' https://app.example.com/admin/users -b 'session=NORMAL_USER'

# Header-based bypasses worth one quick try (some proxies gate on these)
curl -s https://app.example.com/admin/ -b 'session=NORMAL_USER' \
  -H 'X-Original-URL: /admin/' -H 'X-Rewrite-URL: /admin/' -o /dev/null -w '%{http_code}\n'
```

If the app uses JWTs, decode the payload and check whether the server actually validates the signature and the claims — changing `"role":"user"` to `"role":"admin"` in a token whose signature is not verified is a classic vertical escalation (and a client-side trust failure).

## Forced Browsing

Forced browsing (also called direct object/function browsing) means requesting resources the UI never links to. It is how horizontal and vertical tests find their targets.

```bash
# Guess common function paths discovered or inferred in Phase 01
ffuf -u https://app.example.com/FUZZ -w admin-paths.txt \
     -b 'session=NORMAL_USER' -mc 200,201,204,301,302 \
     -fs 1234   # filter default logged-in-user page length

# Verb fuzzing: same path, different methods
for m in GET POST PUT DELETE PATCH OPTIONS; do
  code=$(curl -s -X $m -o /dev/null -w '%{http_code}' \
    https://app.example.com/api/users -b 'session=NORMAL_USER')
  echo "$m -> $code"
done
```

Forced browsing is also how you find *staging* functions: `/api/v2/`, `/admin-test/`, `/debug/users` — often deployed without the access-control wiring of the production copies.

## Testing Techniques to Prove Impact

A finding is only as good as its demonstrated impact. For every access-control issue:

1. **Reproduce with two identities.** Always prove that the access is *cross-identity* or *cross-privilege*, not just "the endpoint exists".
2. **Demonstrate the action.** Reading a colleague's invoice beats reporting that `GET /invoice/5823` returns 200 — capture the differing fields in the response.
3. **Chain only as far as needed.** If you can read another user's data, stop there; do not pivot into modifying it unless that is your explicitly authorized goal.
4. **Collect evidence:** request/response pair showing alice's cookie returning bob's data, timestamps, and the two accounts used.

```bash
# Evidence snippet that makes the finding self-explanatory
# Request (alice's session):
#   GET /api/orders/777001 HTTP/1.1
#   Cookie: session=ALICE_VALID_SESSION
# Response: 200 OK  {"order": {...}, "customer_email": "bob@example.com"}
# Compare: bob sees the identical order with his own session.
```

## Common Mistakes & Tips

- **Only testing the UI.** Modern SPAs check access client-side for cosmetics and trust the API to enforce. Test the API endpoints directly with a low-privilege cookie.
- **Not using two accounts.** Without a second identity (or second object) you cannot distinguish "any logged-in user may see this" from "this is public". Create test accounts early (Phase 01 scope permitting).
- **Confusing IDOR with missing authentication.** If an endpoint works with *no* cookie at all, that is an authentication/authorization gap on a different axis — test both with and without a session.
- **Fuzzing sequential IDs blindly.** A wall of 404s may simply mean IDs are GUIDs; step back and look at how IDs are issued (create two objects and compare).
- **Forgetting write operations.** Read-only IDOR tests miss the worse variant. After proving read access, check whether `PUT`/`POST`/`DELETE` on the same resource is also broken.
- **Ignoring the HTTP method.** `GET /admin` may be blocked while `POST /admin` passes; many frameworks map both to the same handler.
- **Failing to baseline.** Compare every odd response against *your own* legitimate access — otherwise you will report public data as an access-control flaw.

## Checklist / Self-test

- [ ] I control at least two accounts (or two objects) that let me prove cross-identity access.
- [ ] I enumerated the app's functions and marked which privilege level each one should require.
- [ ] I tested direct object references (IDs, filenames, account numbers) by mutating one variable at a time.
- [ ] I verified whether read access escalates to write/delete on the same resource.
- [ ] I attempted forced browsing to admin, staging, and debug functions with a normal-user session.
- [ ] I tested HTTP method variations and common access-control header bypasses.
- [ ] I checked client-side role claims (cookies, headers, JWT payload) for server-side enforcement.
- [ ] Every finding is backed by a two-identity reproduction showing real impact.

## Further Resources

- OWASP Top 10 — A01 Broken Access Control: https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — WSTG-ATHZ (Authorization Testing) chapter, including IDOR and privilege-escalation tests: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — "Access control" and "Insecure direct object references (IDOR)" topics with labs: https://portswigger.net/web-security

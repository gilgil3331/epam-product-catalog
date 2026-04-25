# Product Catalog — EPAM Interview Challenge

A secure Flask web application built as part of the EPAM / White Hat penetration testing role challenge.
Every architectural and code decision maps to a specific parameter in the internal **פרמטרים לפיתוח מאובטח** (Secure Development Parameters) document.

Live demo: https://epam-product-catalog.onrender.com

---

## Functional Scope

Two pages, one table, SQL-only access:

| Page | Route | Auth required | Method |
|---|---|---|---|
| Login | `/login` | No | GET, POST |
| Add Product | `/add` | Yes | GET, POST |
| Search Products | `/search` | Yes | GET |

**Database table:** `products(id, name VARCHAR(100), price NUMERIC(10,2), created_at TIMESTAMPTZ)`

---

## Security Architecture

Each control maps to one or more parameters from the secure development document.

| Layer | Implementation | Parameter |
|---|---|---|
| **Input validation** | Server-side whitelist regex `^[A-Za-z0-9 ]{1,100}$` on name and search; rejects anything not matching before any DB call | INP-1 (רשימה לבנה) |
| **Range validation** | Price: `0 < price ≤ 999,999.99`, rounded to 2 decimals; name: 1–100 chars enforced server-side | INP-3 (בדיקות לוגיות/טווחים) |
| **Database** | All queries use psycopg2 `%s` parameterization; zero string concatenation; LIKE wildcard wrapped server-side: `f"%{val}%"` passed as param | DB-3 (שאילתות מול בסיס נתונים) |
| **DB privileges** | `app_user` role: `SELECT + INSERT` on `products`; `SELECT` on `users`; no UPDATE/DELETE/DROP/schema rights | DB-1 (הרשאות מינימליות) |
| **Secrets** | All secrets in environment variables; `.env` gitignored; `.env.example` committed with placeholder values only | CONF-1 (ניהול תצורה) |
| **Transport** | HTTPS enforced via Render SSL + Flask-Talisman HSTS (`max-age=31536000`) | INT-1, ENC-2 |
| **Security headers** | X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, strict CSP (see below) | PROTO-1, ERR-1 |
| **CSP** | `default-src 'self'`; `script-src 'strict-dynamic' https://www.google.com https://www.gstatic.com`; `frame-src https://www.google.com https://recaptcha.google.com`; `style-src 'self'`; `img-src 'self' data:`; `connect-src 'self' https://www.google.com https://recaptcha.google.com`; per-request nonce injected by Talisman | PROTO-1 |
| **Session cookies** | `Secure=true`, `HttpOnly=true`, `SameSite=Strict`; 1-hour lifetime | Session layer, INT-1 |
| **CSRF protection** | Flask-WTF tokens on all POST forms; token in meta tag for JS reads | CSRF layer |
| **Password hashing** | bcrypt cost factor 12; one-way; plaintext never stored or logged | AUTH-1 (ערבול סיסמאות) |
| **Timing attack prevention** | `_DUMMY_HASH` always compared when username not found — bcrypt always runs regardless of whether user exists | ERR-2 |
| **Error messages** | All error responses use generic text; no stack traces, DB names, table names, or server details in response body; `DEBUG=False` in production | ERR-1, ERR-2 (הודעות שגיאה) |
| **Rate limiting** | Flask-Limiter (in-memory): login `5/min`, add-product `10/min`, search `30/min`; global `200/day 50/hour`; timed auto-release | DOS-1 (חסימת DOS) |
| **Bot prevention** | reCAPTCHA v3 on login and add-product; token verified server-side (`score ≥ 0.5`); no browser-only check | BOT-1 (מניעת בוטים) |
| **Logging** | All requests, failed logins, reCAPTCHA blocks, 4xx/5xx errors logged server-side via Python `logging` | LOG-2 (לוגים) |
| **Log scrubbing** | Regex scrubber strips values from any log message containing: `password`, `token`, `secret`, `key`, `authorization`, `credential` (case-insensitive) — the matched `key=value` pair is replaced with `key=[REDACTED]`; **only `=`-delimited patterns are correctly redacted** (the `:` delimiter form is matched by the regex but not properly replaced due to a bug in the lambda — the value leaks as `key: value=[REDACTED]`) | LOG-3 (לוגים) |
| **No security questions** | Password recovery out of scope; documented gap | REC-1 |
| **Version control** | Git + GitHub; all changes tracked with meaningful commits | VER-1 (ניהול גרסאות) |
| **Dependencies** | All 9 packages pinned to exact versions in `requirements.txt`; no unused packages | Dependency layer |

---

### Known Gaps (documented honestly)

| Gap | Parameter | Remediation for production |
|---|---|---|
| No WAF | PROTO-1 | Add custom domain + Cloudflare Free WAF |
| No SIEM | LOG-1 | Forward Render logs to a SIEM (Datadog, etc.) |
| No password expiry | PASS-2 | Add expiry column to users table; enforce in middleware |
| No OTP password recovery | REC-2 | Integrate email/SMS OTP service |

---

## Endpoints — Full Detail

| Route | Methods | Auth | Rate limit | reCAPTCHA | CSRF |
|---|---|---|---|---|---|
| `/` | GET | No | Global | No | No |
| `/login` | GET, POST | No | 5/min | POST only (v3) | POST |
| `/add` | GET, POST | Yes | 10/min | POST only (v3) | POST |
| `/search` | GET | Yes | 30/min | No | No |
| `/logout` | POST | No | Global | No | Yes |

---

## Validation Rules (server-side, enforced in `validators.py`)

| Field | Rule | Regex / Bound |
|---|---|---|
| Product name | Whitelist only | `^[A-Za-z0-9 ]{1,100}$` |
| Price | Positive float, bounded | `0 < price ≤ 999999.99`, rounded to 2dp |
| Search query | Same whitelist as name | `^[A-Za-z0-9 ]{1,100}$` |
| Username | `strip()` only, no regex | Passed as SQL param; bcrypt comparison always runs |

Note: HTML `pattern` and `min/max` attributes are present on the client but **all validation is re-enforced server-side independently**.

---

## Threat Model

| Attack | Mitigated by | What to test |
|---|---|---|
| SQL Injection | Parameterized queries (DB-3) + whitelist (INP-1) | `' OR 1=1--`, UNION, time-based blind |
| XSS (stored/reflected) | Jinja2 auto-escaping + strict CSP | `<script>`, `"><img onerror=`, event handlers |
| CSRF | Flask-WTF tokens; SameSite=Strict | Replay POST without token; cross-origin POST |
| Brute force | Rate limit 5/min + bcrypt cost 12 | >5 login attempts/min; response time delta |
| Credential stuffing | Same rate limit + reCAPTCHA v3 | Automated login with wordlist |
| Bot attacks | reCAPTCHA v3 server-side score (BOT-1) | Replay old token; submit without token |
| User enumeration | Generic "Invalid credentials" + constant-time bcrypt | Compare response time/body for valid vs invalid user |
| Session hijacking | Secure + HttpOnly + SameSite cookies; HTTPS | Intercept cookie; test over HTTP |
| Clickjacking | X-Frame-Options: DENY | Embed in `<iframe>` |
| Info disclosure | Generic errors; DEBUG=False | Trigger 500; check response body for stack trace |
| Secret leakage | Env vars; .env gitignored | Check git history, JS source, response headers |
| DB privilege escalation | `app_user`: SELECT + INSERT only | Attempt UPDATE/DELETE/DROP via injection |
| Path traversal | No file ops in scope | N/A |
| Dependency CVEs | All packages pinned | `pip-audit` against `requirements.txt` |

---

## Folder Structure

```
product-catalog/
├── .env.example          # Secret template — CONF-1
├── .gitignore            # Blocks .env from repo — CONF-1
├── requirements.txt      # 9 packages, all pinned — Dependency layer
├── wsgi.py               # Gunicorn entry point
├── create_user.py        # Local utility to bcrypt-hash a password
│
├── app/
│   ├── __init__.py       # App factory: Talisman (CSP/HSTS), CSRF, Limiter, blueprints
│   ├── config.py         # Reads secrets from env; RuntimeError if any missing — CONF-1
│   ├── db.py             # Sole DB access point; parameterized queries only — DB-3
│   ├── validators.py     # Whitelist regex + range checks — INP-1, INP-3
│   ├── recaptcha.py      # Server-side reCAPTCHA v3 score verification — BOT-1
│   ├── logger.py         # Structured logging; regex scrubs sensitive field values — LOG-2, LOG-3
│   ├── error_handlers.py # Generic HTTP error responses for 400/403/404/405/429/500 — ERR-1
│   │
│   ├── routes/
│   │   ├── auth.py       # Login (bcrypt, dummy-hash timing, rate-limited) — AUTH-1, DOS-1, ERR-2
│   │   └── products.py   # Add + Search (validated, rate-limited, CAPTCHA-gated, login-required)
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── main.css          # Application styles
│   │   ├── js/
│   │   │   └── recaptcha.js      # reCAPTCHA token fetch before form submit; external file required by CSP (no unsafe-inline)
│   │   └── favicon.svg
│   │
│   └── templates/
│       ├── base.html     # CSP nonce injection, CSRF meta tag, nav
│       ├── login.html    # reCAPTCHA v3 hidden field populated by recaptcha.js
│       ├── add_product.html  # reCAPTCHA v3; client-side pattern mirrors server regex
│       ├── search.html   # Output escaped by Jinja2
│       └── error.html    # Generic error page
```

---

## Local Development

```bash
git clone https://github.com/gilgil3331/spam-product-catalog.git
cd spam-product-catalog
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your real values
FLASK_ENV=development flask --app wsgi:app run
```

> **Note:** The GitHub repository was accidentally named `spam-product-catalog` instead of `epam-product-catalog`. The clone URL above is correct; the name is a typo and does not affect functionality.

> With `FLASK_ENV=development`: DEBUG on, HTTPS not enforced, reCAPTCHA check skipped entirely server-side (`recaptcha.py` returns `True` immediately without examining the token), session cookie Secure flag off.

---

## Database Setup (Supabase)

```sql
CREATE TABLE products (
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    price      NUMERIC(10, 2) NOT NULL CHECK (price > 0),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Minimal privileges for the app user (DB-1)
CREATE ROLE app_user WITH LOGIN PASSWORD 'STRONG_PASSWORD';
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT ON TABLE products TO app_user;
GRANT SELECT ON TABLE users TO app_user;
GRANT USAGE, SELECT ON SEQUENCE products_id_seq TO app_user;
```

---

## Security Self-Audit Checklist

- [ ] **INP-1** — All inputs validated server-side with `^[A-Za-z0-9 ]{1,100}$` before any DB call; HTML pattern is a UX hint only
- [ ] **INP-3** — Price validated: `0 < price ≤ 999,999.99`; enforced in `validators.py` independently of HTML `min/max`
- [ ] **DB-3** — Zero dynamic SQL; all queries use psycopg2 `%s` params; LIKE wildcard injected server-side not client-side
- [ ] **DB-1** — `app_user` has no UPDATE, DELETE, DROP, or schema-level rights; verified in Supabase role grants
- [ ] **CONF-1** — `.env` gitignored; no secret in any committed file; `config.py` raises `RuntimeError` if env var missing
- [ ] **INT-1** — HTTPS enforced; `Strict-Transport-Security: max-age=31536000` present in all production responses
- [ ] **AUTH-1** — Password stored as bcrypt hash (`$2b$12$…`); plaintext never stored or logged
- [ ] **ERR-2** — Login returns identical body and timing for wrong password vs unknown username
- [ ] **ERR-1** — 500 errors return generic message; no stack trace, module path, or DB detail in response body
- [ ] **DOS-1** — Rate limits active: 429 returned after 5 login POST/min, 10 add POST/min, 30 search GET/min
- [ ] **BOT-1** — reCAPTCHA v3 verified server-side; empty or replayed token returns 400 "Verification failed"
- [ ] **LOG-2** — Failed logins, reCAPTCHA blocks, and 5xx errors appear in server logs with IP and username
- [ ] **LOG-3** — No password, token, or secret value appears in any log line; scrubber replaces `key=value` with `key=[REDACTED]` (note: `:` delimiter form not fully redacted — known bug in `logger.py`)
- [ ] **PROTO-1** — `X-Frame-Options: DENY`; `X-Content-Type-Options: nosniff`; CSP blocks inline scripts and unlisted origins
- [ ] **VER-1** — All changes tracked in Git; no secrets in git history

# Product Catalog

A secure Flask web application with two pages: add a product (name + price) and search products. Built with security-first design — every layer addresses a concrete attack vector.

**Live demo:** https://challange1-product-catalog.fly.dev/

---

## Tech Stack

| Component | Choice |
|---|---|
| Language / Framework | Python 3.12 + Flask |
| Database | PostgreSQL (Supabase, eu-west-1) |
| Hosting | Fly.io, Frankfurt region — always-on |
| Web server | Gunicorn |
| Key libraries | Flask-WTF, Flask-Limiter, Flask-Talisman, psycopg2-binary, bcrypt |

---

## Functional Scope

| Page | Route | Auth required | Method |
|---|---|---|---|
| Login | `/login` | No | GET, POST |
| Add Product | `/add` | Yes | GET, POST |
| Search Products | `/search` | Yes | GET |

**Database table:** `products(id, name VARCHAR(100), price NUMERIC(10,2), created_at TIMESTAMPTZ)`

---

## Security Architecture

| Layer | Implementation |
|---|---|
| **Input validation** | Server-side whitelist regex `^[A-Za-z0-9 ]{1,100}$` on name and search; rejects anything not matching before any DB call |
| **Range validation** | Price: `0 < price ≤ 999,999.99`, rounded to 2 decimals; name: 1–100 chars enforced server-side |
| **SQL injection prevention** | All queries use psycopg2 `%s` parameterization; zero string concatenation; LIKE wildcard wrapped server-side as a parameter |
| **DB least privilege** | `app_user` role: `SELECT + INSERT` on `products`; `SELECT` on `users` only; no UPDATE/DELETE/DROP/schema rights |
| **Secrets management** | All secrets in environment variables; `.env` gitignored; `.env.example` committed with placeholder values only; `config.py` raises `RuntimeError` if any env var is missing at startup |
| **Transport security** | HTTPS enforced via Fly.io + Flask-Talisman HSTS (`max-age=31536000`) |
| **Security headers** | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` |
| **Content Security Policy** | `default-src 'self'`; `script-src 'strict-dynamic'` + google/gstatic; `frame-src` google/recaptcha; `style-src 'self'`; `img-src 'self' data:`; `connect-src 'self'` + google/recaptcha; per-request nonce injected by Talisman |
| **Session cookies** | `Secure=true`, `HttpOnly=true`, `SameSite=Strict`; 1-hour lifetime |
| **CSRF protection** | Flask-WTF tokens on all POST forms; token exposed via meta tag for JS reads |
| **Password hashing** | bcrypt cost factor 12; one-way; plaintext never stored or logged |
| **Timing attack prevention** | `_DUMMY_HASH` always compared when username not found — bcrypt always runs regardless of whether user exists, preventing user enumeration via response time |
| **Error messages** | All error responses use generic text; no stack traces, DB names, table names, or server details in response body; `DEBUG=False` in production |
| **Rate limiting** | Flask-Limiter (in-memory): login `5/min`, add-product `10/min`, search `30/min`; global `200/day 50/hour` |
| **Bot prevention** | reCAPTCHA v3 on login and add-product; token verified server-side (`score ≥ 0.5`); no browser-only check |
| **Logging** | All requests, failed logins, reCAPTCHA blocks, 4xx/5xx errors logged server-side |
| **Log scrubbing** | Regex scrubber replaces values of sensitive fields (`password`, `token`, `secret`, `key`, `authorization`, `credential`) with `[REDACTED]` in all log output |
| **Version control** | Git + GitHub; all changes tracked; no secrets in git history |
| **Dependencies** | All 9 packages pinned to exact versions; no unused packages |

---

### Known Gaps

| Gap | Remediation for production |
|---|---|
| No WAF | Add custom domain + Cloudflare Free WAF |
| No SIEM | Forward Fly.io logs to a SIEM (Datadog, etc.) |
| No password expiry | Add expiry column to users table; enforce in middleware |
| No OTP password recovery | Integrate email/SMS OTP service |
| Log scrubber bug | `logger.py` correctly redacts `key=value` patterns but not `key: value` (colon-delimited) — the value leaks as `key: value=[REDACTED]` due to a bug in the lambda |

---

## Endpoints

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
| SQL Injection | Parameterized queries + whitelist input validation | `' OR 1=1--`, UNION, time-based blind |
| XSS (stored/reflected) | Jinja2 auto-escaping + strict CSP | `<script>`, `"><img onerror=`, event handlers |
| CSRF | Flask-WTF tokens; SameSite=Strict | Replay POST without token; cross-origin POST |
| Brute force | Rate limit 5/min + bcrypt cost 12 | >5 login attempts/min; response time delta |
| Credential stuffing | Rate limit + reCAPTCHA v3 | Automated login with wordlist |
| Bot attacks | reCAPTCHA v3 server-side score | Replay old token; submit without token |
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
├── .env.example          # Secret template with placeholder values only
├── .gitignore            # Blocks .env from repo
├── requirements.txt      # 9 packages, all pinned to exact versions
├── wsgi.py               # Gunicorn entry point
├── create_user.py        # Local utility to bcrypt-hash a password
│
├── app/
│   ├── __init__.py       # App factory: Talisman (CSP/HSTS), CSRF, Limiter, blueprints
│   ├── config.py         # Reads secrets from env; RuntimeError if any missing
│   ├── db.py             # Sole DB access point; parameterized queries only
│   ├── validators.py     # Whitelist regex + range checks
│   ├── recaptcha.py      # Server-side reCAPTCHA v3 score verification
│   ├── logger.py         # Structured logging; regex scrubs sensitive field values
│   ├── error_handlers.py # Generic HTTP error responses for 400/403/404/405/429/500
│   │
│   ├── routes/
│   │   ├── auth.py       # Login (bcrypt, dummy-hash timing, rate-limited)
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
│       ├── base.html         # CSP nonce injection, CSRF meta tag, nav
│       ├── login.html        # reCAPTCHA v3 hidden field populated by recaptcha.js
│       ├── add_product.html  # reCAPTCHA v3; client-side pattern mirrors server regex
│       ├── search.html       # Output escaped by Jinja2
│       └── error.html        # Generic error page
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

## Database Setup

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

-- Minimal privileges: app_user cannot UPDATE, DELETE, DROP, or access schema
CREATE ROLE app_user WITH LOGIN PASSWORD 'STRONG_PASSWORD';
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT ON TABLE products TO app_user;
GRANT SELECT ON TABLE users TO app_user;
GRANT USAGE, SELECT ON SEQUENCE products_id_seq TO app_user;
```

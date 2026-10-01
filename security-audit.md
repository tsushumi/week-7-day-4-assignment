# Security Audit

Audit of the vulnerable Express server provided for Task 3. Seven
vulnerabilities were found (the assignment asked for at least six).

---

## 1. Plaintext Password Storage

**Where:** `app.post("/api/register", ...)`
```javascript
users.push({ id: users.length + 1, email, password, name });
```

**Why it's dangerous:** The password is stored exactly as the user typed
it, with no hashing at all. Anyone who reads the `users` array — via a
database dump, a backup, a log line, an injected query (see #4), or just
insider access — gets every user's real password in plain text. Because
people reuse passwords, this one leak compromises accounts on other sites
too.

**Fix:** Hash with bcrypt (or argon2) before storing, and never keep the
plaintext around:

```javascript
import bcrypt from "bcryptjs";

app.post("/api/register", async (req, res) => {
  const { email, password, name } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, email, passwordHash, name });
  res.status(201).json({ message: "Registered", user: { email, name } });
});
```

---

## 2. Password Returned in the API Response

**Where:** `app.post("/api/register", ...)`
```javascript
res.json({ message: "Registered", user: { email, password, name } });
```

**Why it's dangerous:** Even if the password were hashed, echoing any form
of it back to the client is unnecessary and risky — it ends up in browser
dev tools, proxy/CDN logs, error-tracking tools, and anywhere else the
response is captured. There's never a legitimate reason for a response to
contain a password or its hash.

**Fix:** Only return non-sensitive fields (see the combined fix in #1
above — the response omits `password`/`passwordHash` entirely).

---

## 3. Hardcoded JWT Secret

**Where:**
```javascript
const JWT_SECRET = "my-app-secret-123";
```

**Why it's dangerous:** A secret committed to source code is visible to
anyone with repo access (including, eventually, on GitHub if the repo is
or becomes public) and is identical across every environment. If it
leaks, an attacker can forge valid JWTs for any user — including an
admin — with no way to fix it except rotating the secret and invalidating
every existing token.

**Fix:** Load it from an environment variable, generate it randomly, and
never commit it:

```javascript
// .env (gitignored)
// JWT_SECRET=<openssl rand -hex 32>

import dotenv from "dotenv";
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not set");
}
```

---

## 4. SQL Injection

**Where:** `app.get("/api/users/search", ...)`
```javascript
const result = db.query(`SELECT * FROM users WHERE name = '${name}'`);
```

**Why it's dangerous:** The `name` query parameter is concatenated
directly into raw SQL. A request like
`/api/users/search?name=' OR '1'='1` returns every row in the table;
something like `'; DROP TABLE users; --` can destroy data outright, and a
more patient attacker can use this to exfiltrate the entire database
(including the plaintext passwords from #1).

**Fix:** Use parameterized queries — never build SQL with string
interpolation:

```javascript
app.get("/api/users/search", (req, res) => {
  const { name } = req.query;
  const result = db.query("SELECT id, email, name FROM users WHERE name = $1", [name]);
  res.json(result);
});
```
(Also note the fix selects specific columns rather than `SELECT *`, so a
password/password hash column can't leak through this endpoint either.)

---

## 5. Cross-Site Scripting (XSS)

**Where:** `app.get("/api/comments/:id", ...)`
```javascript
res.send(`<html><body><p>${comment.text}</p></body></html>`);
```

**Why it's dangerous:** User-controlled content (`comment.text`) is
dropped directly into an HTML response with no escaping. Here it's a
hardcoded example, but in a real app `comment.text` would come from user
input, so any `<script>` or event-handler payload a user submits gets
executed in the browser of everyone who views that comment — enabling
session/cookie theft, keylogging, or actions performed as the victim
(stored XSS).

**Fix:** Escape user-generated content before interpolating it into HTML,
or better, don't hand-build HTML at all — return JSON and let the
frontend render it safely (React/Vue auto-escape text by default):

```javascript
import { escape } from "html-escaper"; // or any equivalent helper

app.get("/api/comments/:id", (req, res) => {
  const comment = { text: "<script>alert('XSS')</script>Malicious comment" };
  res.json({ comment: { text: comment.text } }); // let the frontend escape on render
  // or, if HTML must be returned directly:
  // res.send(`<html><body><p>${escape(comment.text)}</p></body></html>`);
});
```

---

## 6. CORS Misconfiguration — Allow Every Origin

**Where:**
```javascript
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});
```

**Why it's dangerous:** This lets **any** website make authenticated
requests to this API from a victim's browser. Combined with cookie-based
auth it would let a malicious site ride the victim's session; even with
header-based auth it still exposes every endpoint to being called from
arbitrary origins, aiding CSRF-style and data-scraping attacks and
defeating the purpose of CORS as a protection.

**Fix:** Restrict to the specific origin(s) that should be allowed, via
the `cors` package:

```javascript
import cors from "cors";
app.use(cors({ origin: "https://your-frontend.example.com" }));
```

---

## 7. Sensitive Information Disclosure in the Error Handler

**Where:**
```javascript
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    dbConnection: "postgresql://admin:password123@db.example.com:5432/myapp",
  });
});
```

**Why it's dangerous:** This hands any client that triggers a 500 error
the full stack trace (which can reveal file paths, internal library
versions, and logic) **and** a live database connection string with
plaintext credentials. An attacker who finds any route that throws gets
direct, authenticated access to the production database.

**Fix:** Log detailed errors server-side only; send the client a generic
message (and never put secrets in an error payload at all):

```javascript
app.use((err, req, res, next) => {
  console.error(err); // full detail goes to server logs, not the client
  res.status(500).json({ error: "Internal server error" });
});
```

---

## Summary table

| # | Vulnerability | Location | Severity |
|---|---|---|---|
| 1 | Plaintext password storage | `/api/register` | Critical |
| 2 | Password returned in response | `/api/register` | High |
| 3 | Hardcoded JWT secret | top-level constant | Critical |
| 4 | SQL injection | `/api/users/search` | Critical |
| 5 | XSS (unescaped HTML output) | `/api/comments/:id` | High |
| 6 | CORS allows all origins | global middleware | Medium-High |
| 7 | Stack trace & DB credentials leaked in errors | error handler | Critical |

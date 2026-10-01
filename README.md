# Week 7, Day 4 — Role-Based & Resource-Level Authorization

An Express API with `authenticate` (JWT) + `authorize(...roles)`
middleware for role-based access control, resource-level ownership checks
on posts, a written security audit (Task 3), and a bonus cookie + CSRF
flow.

## Setup

```bash
git clone <this-repo-url>
npm install
```

```bash
node server.js
# Server listening on http://localhost:3000
```

### Test credentials (seeded on startup)

Passwords are hashed with bcrypt at startup — these plaintext values are
only here so you can log in and get a token for each role:

| Email | Password | Role |
|---|---|---|
| `admin@mail.com` | `Admin123` | ADMIN |
| `editor@mail.com` | `Editor123` | EDITOR |
| `wanjiku@mail.com` | `Wanjiku123` | USER |
| `ochieng@mail.com` | `Ochieng123` | USER |

Get a token for any of them:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@mail.com", "password": "Admin123"}'
```

---

## Task 1: role-based authorization (`authorize(...roles)`)

```bash
# Admin accessing admin route
curl http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer ADMIN_TOKEN"
```
```json
200
{"users":[{"id":1,"email":"admin@mail.com","name":"Admin User","role":"ADMIN"},{"id":2,"email":"editor@mail.com","name":"Editor User","role":"EDITOR"},{"id":3,"email":"wanjiku@mail.com","name":"Wanjiku","role":"USER"},{"id":4,"email":"ochieng@mail.com","name":"Ochieng","role":"USER"}]}
```

```bash
# Regular user trying the admin route
curl http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer USER_TOKEN"
```
```json
403
{"error":"Access denied. You do not have permission to perform this action.","requiredRoles":["ADMIN"],"yourRole":"USER"}
```

```bash
# Editor accessing the editor route
curl http://localhost:3000/api/editor/posts \
  -H "Authorization: Bearer EDITOR_TOKEN"
```
```json
200
{"posts":[{"id":1,"title":"My First Post","content":"Hello world","userId":3},{"id":2,"title":"Express Tips","content":"Middleware is powerful","userId":4},{"id":3,"title":"Nairobi Guide","content":"Best restaurants in Westlands","userId":3}]}
```

```bash
# A plain USER only sees their own posts
curl http://localhost:3000/api/posts \
  -H "Authorization: Bearer WANJIKU_TOKEN"
```
```json
200
{"posts":[{"id":1,"title":"My First Post","content":"Hello world","userId":3},{"id":3,"title":"Nairobi Guide","content":"Best restaurants in Westlands","userId":3}]}
```

```bash
# Admin promotes the editor to ADMIN
curl -X PATCH http://localhost:3000/api/admin/users/2/role \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "ADMIN"}'
```
```json
200
{"user":{"id":2,"email":"editor@mail.com","name":"Editor User","role":"ADMIN"}}
```

```bash
# Admin tries to change their OWN role
curl -X PATCH http://localhost:3000/api/admin/users/1/role \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "USER"}'
```
```json
403
{"error":"Admins cannot change their own role"}
```

```bash
# Invalid role value
curl -X PATCH http://localhost:3000/api/admin/users/3/role \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "SUPERUSER"}'
```
```json
400
{"error":"Role must be one of: USER, EDITOR, ADMIN"}
```

---

## Task 2: resource-level authorization (post ownership)

```bash
# Any authenticated user can view a single post
curl http://localhost:3000/api/posts/1 \
  -H "Authorization: Bearer OCHIENG_TOKEN"
```
```json
200
{"post":{"id":1,"title":"My First Post","content":"Hello world","userId":3}}
```

```bash
# Wanjiku (user 3) editing her own post (post 1)
curl -X PUT http://localhost:3000/api/posts/1 \
  -H "Authorization: Bearer WANJIKU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Updated Title"}'
```
```json
200
{"post":{"id":1,"title":"Updated Title","content":"Hello world","userId":3}}
```

```bash
# Ochieng (user 4) trying to edit Wanjiku's post
curl -X PUT http://localhost:3000/api/posts/1 \
  -H "Authorization: Bearer OCHIENG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Hacked Title"}'
```
```json
403
{"error":"You can only edit your own posts"}
```

```bash
# Admin editing Wanjiku's post
curl -X PUT http://localhost:3000/api/posts/1 \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Admin Updated"}'
```
```json
200
{"post":{"id":1,"title":"Admin Updated","content":"Hello world","userId":3}}
```

```bash
curl -X DELETE http://localhost:3000/api/posts/999 \
  -H "Authorization: Bearer ADMIN_TOKEN"
```
```json
404
{"error":"Post not found"}
```

```bash
# Wanjiku tries to delete Ochieng's post
curl -X DELETE http://localhost:3000/api/posts/2 \
  -H "Authorization: Bearer WANJIKU_TOKEN"
```
```json
403
{"error":"You can only delete your own posts"}
```

```bash
# Ochieng deletes his own post
curl -X DELETE http://localhost:3000/api/posts/2 \
  -H "Authorization: Bearer OCHIENG_TOKEN"
```
```json
200
{"message":"Post deleted"}
```

---

## Task 3: security audit

See **[`security-audit.md`](./security-audit.md)** — seven vulnerabilities
in the provided code (plaintext passwords, password echoed in responses,
hardcoded JWT secret, SQL injection, XSS, wide-open CORS, and stack
trace/DB-credential leakage in the error handler), each with its location,
why it's dangerous, and the fixed code.

---

## Bonus: cookie-based auth + CSRF protection

```bash
# 1. Log in — sets an httpOnly cookie instead of returning the token in JSON
curl -c cookies.txt -X POST http://localhost:3000/api/auth/login-cookie \
  -H "Content-Type: application/json" \
  -d '{"email": "wanjiku@mail.com", "password": "Wanjiku123"}'
```
```json
200
{"message":"Login successful","user":{"id":3,"email":"wanjiku@mail.com","name":"Wanjiku","role":"USER"}}
```

```bash
# 2. Fetch a CSRF token for this session (cookie required)
curl -b cookies.txt http://localhost:3000/api/csrf-token
```
```json
{"csrfToken":"47b5445917e3257331835abe1a1dc84d37e1a518fd996892d9080d20064fafd1"}
```

```bash
# 3. State-changing request WITHOUT the CSRF header → rejected
curl -b cookies.txt -X POST http://localhost:3000/api/secure/posts \
  -H "Content-Type: application/json" \
  -d '{"title": "No CSRF token", "content": "should fail"}'
```
```json
403
{"error":"Invalid CSRF token"}
```

```bash
# 4. Same request WITH the correct header → succeeds
curl -b cookies.txt -X POST http://localhost:3000/api/secure/posts \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: 47b5445917e3257331835abe1a1dc84d37e1a518fd996892d9080d20064fafd1" \
  -d '{"title": "CSRF protected post", "content": "this should work"}'
```
```json
201
{"post":{"id":4,"title":"CSRF protected post","content":"this should work","userId":3}}
```

```bash
# 5. Wrong token → still rejected
curl -b cookies.txt -X POST http://localhost:3000/api/secure/posts \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: not-the-right-token" \
  -d '{"title": "Should fail", "content": "wrong token"}'
```
```json
403
{"error":"Invalid CSRF token"}
```

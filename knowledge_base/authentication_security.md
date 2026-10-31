# Authentication Security — Missing Authentication and Weak Token Handling

## What Is Missing Authentication?

Missing authentication occurs when an API endpoint does not require any form of identity verification. Any internet user can call the endpoint without providing credentials.

## Simple English Explanation

Think of a house with a locked front door. Missing authentication means the door is open — anyone can walk in.

A login endpoint should require a username and password. An API endpoint that returns user data should require a valid session token. If either of those checks is absent, that is missing authentication.

## Root Cause

- Authentication middleware absent from route
- Middleware applied globally but excluded for specific paths by mistake
- Token validation logic is present but not enforced (validation is optional)

## OWASP Reference

OWASP API Security Top 10 — API2:2023

CWE-306: Missing Authentication for Critical Function

## Common Vulnerable Patterns

```javascript
// VULNERABLE — no authentication check
app.get('/api/user/profile', (req, res) => {
  const user = db.getUserById(req.query.id);
  res.json(user);
});

// SECURE
app.get('/api/user/profile', verifyToken, (req, res) => {
  const user = db.getUserById(req.user.id);  // use verified identity
  res.json(user);
});
```

## JWT Security

JSON Web Tokens are commonly used for authentication. Key vulnerabilities:

### Algorithm Confusion (None Algorithm)

```
// Attacker crafts a JWT with alg: none
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

**Fix:** Always verify the algorithm matches the expected value. Never accept `alg: none`.

### Signature Verification Missing

```python
# VULNERABLE
payload = jwt.decode(token, options={"verify_signature": False})

# SECURE
payload = jwt.decode(token, secret_key, algorithms=["HS256"])
```

### Weak Secret Keys

**Fix:** Use at least 256-bit randomly generated secrets. Store secrets in environment variables, never in code.

## Session Management

- Session tokens must be cryptographically random (min 128 bits)
- Tokens must expire (typical: 15 min access, 7 day refresh)
- Tokens must be invalidated on logout
- Never transmit tokens in URL query strings

## Retesting

1. Identify an endpoint that should require authentication
2. Send a request with no Authorization header or cookie
3. Expected: HTTP 401 Unauthorized
4. Missing authentication confirmed if HTTP 200 is returned


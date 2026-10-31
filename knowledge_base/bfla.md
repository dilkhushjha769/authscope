# BFLA — Broken Function Level Authorization

## What Is BFLA?

Broken Function Level Authorization (BFLA) occurs when API functions intended only for privileged roles (administrators) are accessible to lower-privileged users or unauthenticated callers.

## Simple English Explanation

Imagine a web shop. The admin panel at `/api/admin/users` is hidden from the user interface, but the URL still works when a regular user requests it directly. The server checked nothing — it just served the response.

This is BFLA: the function (admin user list) is broken because any user can call it.

## Root Cause

- Server relies on UI hiding instead of server-side role checks
- Role middleware is missing from route definitions
- Administrative routes are not in a protected router group

## OWASP Reference

OWASP API Security Top 10 — API5:2023

CWE-862: Missing Authorization

## Common Patterns

1. **Hidden admin endpoints:** `/api/admin/...` reachable by regular users
2. **HTTP method escalation:** `GET /resource` is public; `DELETE /resource` is not protected
3. **Role assumption:** Passing `role=admin` in a request body and having it accepted
4. **Unauthenticated admin access:** Admin endpoints return data without any token

## Detection

AuthScope detects BFLA by:
1. Identifying privileged or administrative endpoints during discovery
2. Sending requests as an unauthenticated caller or low-privileged user
3. Checking whether the server returns HTTP 401/403 or serves the response

## Remediation

### Express.js Middleware

```javascript
// VULNERABLE
app.get('/api/admin/users', getAllUsers);

// SECURE
app.get('/api/admin/users', verifyToken, requireRole('admin'), getAllUsers);

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}
```

### FastAPI / Python

```python
# VULNERABLE
@router.get("/admin/users")
async def get_all_users():
    return db.query(User).all()

# SECURE
@router.get("/admin/users")
async def get_all_users(current_user: User = Depends(require_admin)):
    return db.query(User).all()

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
```

## Retesting

1. Identify an administrative endpoint
2. Send a request with no authentication token
3. Send a request with a low-privileged user's token
4. Expected: HTTP 401 (unauthenticated) and HTTP 403 (low-privilege)
5. BFLA confirmed if HTTP 200 is returned in either case


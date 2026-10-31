# BOLA / IDOR — Broken Object Level Authorization

## What Is BOLA?

Broken Object Level Authorization (BOLA), also known as Insecure Direct Object Reference (IDOR), occurs when an API endpoint allows users to access objects they do not own simply by changing an identifier in the request.

## Simple English Explanation

Imagine a shopping app. After logging in, your basket is at `/api/baskets/42`. If you can also access `/api/baskets/43` (someone else's basket) without receiving an error, the API has BOLA.

The application trusts the number in the URL without checking whether it belongs to you.

## Root Cause

- Server-side database queries use user-supplied IDs directly
- No ownership or tenancy check is performed
- Example: `SELECT * FROM baskets WHERE id = ?` — missing `AND user_id = ?`

## OWASP Reference

OWASP API Security Top 10 — API1:2023

CWE-639: Authorization Bypass Through User-Controlled Key

## Common Patterns

1. **Numeric ID enumeration:** `/api/orders/100`, `/api/orders/101`, ...
2. **UUID substitution:** replacing your UUID with another user's UUID
3. **Indirect references:** `/profile?user=alice` — changing `alice` to another username
4. **Nested resource access:** `/api/users/42/documents/99` — Document 99 may belong to User 1

## Detection

AuthScope detects BOLA by:
1. Authenticating as User A and obtaining a resource ID
2. Authenticating as User B and requesting User A's resource
3. Confirming the server returns HTTP 200 with User A's data instead of 401/403

## Remediation

### Server-Side Ownership Check

Always include the authenticated user's identity in data queries:

```python
# VULNERABLE
basket = Basket.query.filter_by(id=basket_id).first()

# SECURE
basket = Basket.query.filter_by(id=basket_id, user_id=current_user.id).first()
if basket is None:
    return {"error": "Not found or access denied"}, 403
```

### Node.js / Express

```javascript
// VULNERABLE
const basket = await Basket.findByPk(req.params.id);

// SECURE
const basket = await Basket.findOne({
  where: { id: req.params.id, UserId: req.user.id }
});
if (!basket) return res.status(403).json({ error: 'Access denied' });
```

## Retesting

1. Log in as User B
2. Obtain the resource ID of a resource owned by User A
3. Issue `GET /api/resource/{user_a_resource_id}` with User B's session
4. Expected: HTTP 403 Forbidden or HTTP 404 Not Found
5. Vulnerability confirmed if: HTTP 200 with User A's private data is returned


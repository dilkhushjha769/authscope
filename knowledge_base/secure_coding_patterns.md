# Secure Coding Patterns for Authorization

## Principle 1: Default Deny

Every endpoint must deny access by default. Access must be explicitly granted.

```python
# BAD — allows access if check is skipped or exception swallowed
def get_resource(resource_id, user):
    try:
        check_permission(user, resource_id)
    except:
        pass  # Silently skipped — access granted anyway
    return db.get(resource_id)

# GOOD — explicit denial
def get_resource(resource_id: int, user: User) -> Resource:
    resource = db.query(Resource).filter_by(id=resource_id, owner_id=user.id).first()
    if resource is None:
        raise PermissionDeniedError("Access denied or resource not found")
    return resource
```

## Principle 2: Verify Server-Side, Not Client-Side

Never trust client-supplied role claims or permission flags.

```javascript
// BAD — trusting client-supplied role
app.post('/admin/action', (req, res) => {
  if (req.body.role === 'admin') {  // ← attacker-controlled!
    performAdminAction();
  }
});

// GOOD — verify from authenticated session
app.post('/admin/action', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  performAdminAction();
});
```

## Principle 3: Ownership Validation

Always bind resource queries to the authenticated user's identity.

```python
# SECURE pattern — scoped query
def get_user_order(order_id: int, current_user: User) -> Order:
    order = (
        db.query(Order)
        .filter(Order.id == order_id, Order.user_id == current_user.id)
        .first()
    )
    if not order:
        raise HTTPException(status_code=404, detail="Not found")
    return order
```

## Principle 4: Structured Input Validation

Use typed schemas for every API input.

```python
from pydantic import BaseModel
from typing import Optional

class UpdateProfileRequest(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    # Omitting: role, is_admin, email_verified — these cannot be set via this endpoint
```

## Principle 5: Centralize Authorization Logic

Avoid scattering permission checks across handlers. Use a single authorization service.

```python
class AuthorizationService:
    def assert_can_read(self, user: User, resource: Resource) -> None:
        if resource.owner_id != user.id and not user.is_admin:
            raise PermissionDeniedError(f"User {user.id} cannot read resource {resource.id}")

    def assert_can_admin(self, user: User) -> None:
        if not user.is_admin:
            raise PermissionDeniedError("Admin access required")
```

## Principle 6: Test Authorization Explicitly

Write dedicated tests for unauthorized access paths.

```python
def test_user_b_cannot_read_user_a_resource(client, user_a_token, user_b_token):
    resource = create_resource(client, user_a_token)
    response = client.get(f"/api/resource/{resource.id}",
                          headers={"Authorization": f"Bearer {user_b_token}"})
    assert response.status_code in (403, 404)
```


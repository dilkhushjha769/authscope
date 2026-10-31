# Privilege Escalation Vulnerabilities

## What Is Privilege Escalation?

Privilege escalation occurs when a user gains access to resources, data, or capabilities beyond what their role should allow. It can be horizontal (accessing another user's data at the same level) or vertical (gaining higher-privilege capabilities).

## Types

### Horizontal Privilege Escalation
Accessing another user's resources at the same privilege level. See also: BOLA/IDOR.

### Vertical Privilege Escalation
A regular user gains admin-level capabilities. See also: BFLA.

## Common Attack Patterns

### Parameter Tampering
```
POST /api/changeRole
{"userId": 42, "newRole": "admin"}
```
If the server does not validate that only admins can change roles, any user can escalate.

### JWT Claim Manipulation
An attacker modifies the JWT payload to include `"role": "admin"` and submits it. If the server does not verify the signature, the claim is accepted.

### Cookie/Session Manipulation
Modifying session attributes stored client-side (insecure cookies without signing).

## OWASP Reference

OWASP API Security Top 10 — API5:2023 (BFLA)

CWE-269: Improper Privilege Management

## Remediation

```python
# FastAPI — role-based access control

from enum import Enum
from fastapi import Depends, HTTPException

class Role(str, Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"

def require_role(*roles: Role):
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return current_user
    return dependency

# Usage
@router.post("/admin/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    new_role: Role,
    _admin: User = Depends(require_role(Role.ADMIN))
):
    ...
```

## Detection

1. Authenticate as a regular user
2. Attempt to call admin-only endpoints
3. Attempt to modify role or privilege fields in update requests
4. Verify server returns 403 Forbidden for all such attempts


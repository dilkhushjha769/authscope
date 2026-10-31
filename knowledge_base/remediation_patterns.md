# Remediation Patterns — Framework-Specific Fixes

## Node.js / Express

### Add Authentication Middleware

```javascript
const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    req.user = jwt.verify(header.slice(7), process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    next();
  };
}
```

### Fix BOLA in Sequelize

```javascript
// Before (vulnerable)
const item = await Item.findByPk(req.params.id);

// After (secure)
const item = await Item.findOne({
  where: { id: req.params.id, userId: req.user.id }
});
if (!item) return res.status(404).json({ error: 'Not found' });
```

## Python / FastAPI

### Add JWT Authentication Dependency

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise ValueError("Missing sub claim")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

### Fix BOLA in SQLAlchemy

```python
# Before (vulnerable)
item = db.query(Item).filter(Item.id == item_id).first()

# After (secure)
item = (
    db.query(Item)
    .filter(Item.id == item_id, Item.owner_id == current_user.id)
    .first()
)
if item is None:
    raise HTTPException(status_code=404, detail="Not found or access denied")
```

## Django / DRF

### Object-Level Permissions

```python
from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class ItemViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwner]

    def get_queryset(self):
        # Extra safety: scope queryset to current user
        return Item.objects.filter(owner=self.request.user)
```

## General Remediation Checklist

- [ ] Add `authenticate()` middleware to every protected route
- [ ] Add `authorize()` ownership check to every resource endpoint
- [ ] Define explicit input schemas — no mass assignment
- [ ] Return 404 (not 403) for owned resources when the record is not found (avoids enumeration)
- [ ] Write cross-user access tests for every resource type
- [ ] Run SAST (Semgrep, Bandit) against authorization patterns
- [ ] Perform a monthly API inventory audit to detect orphaned endpoints


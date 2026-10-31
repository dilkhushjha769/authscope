# Mass Assignment Vulnerabilities

## What Is Mass Assignment?

Mass assignment occurs when an API endpoint automatically binds all user-supplied input fields to object properties, including fields that should be read-only or restricted.

## Simple English Explanation

Imagine a user profile form. It lets you update your name and email. But the server binds all incoming JSON fields to the User model — including fields like `isAdmin`, `role`, or `balance`.

If an attacker adds `"isAdmin": true` to the JSON body, they may gain admin privileges.

## Root Cause

- ORM or framework automatically maps request body to model attributes
- No allowlist of writable fields is defined
- No blocklist of sensitive/protected fields is enforced

## OWASP Reference

OWASP API Security Top 10 — API3:2023

CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## Vulnerable Patterns

```javascript
// VULNERABLE — Express.js with Mongoose
app.put('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);  // ALL fields from body applied
  await user.save();
  res.json(user);
});

// SECURE — explicit allowlist
app.put('/api/users/:id', async (req, res) => {
  const allowed = ['name', 'email', 'bio'];
  const updates = {};
  for (const field of allowed) {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  }
  const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true });
  res.json(user);
});
```

```python
# VULNERABLE — SQLAlchemy
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    user = User.query.get(current_user.id)
    for key, value in request.json.items():
        setattr(user, key, value)  # ALL fields applied
    db.session.commit()

# SECURE — Pydantic allowlist
class ProfileUpdateRequest(BaseModel):
    name: Optional[str]
    email: Optional[str]
    bio: Optional[str]
    # role, is_admin, balance etc. are deliberately ABSENT

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    data = ProfileUpdateRequest(**request.json)
    user = User.query.get(current_user.id)
    if data.name: user.name = data.name
    if data.email: user.email = data.email
    db.session.commit()
```

## Detection

1. Identify an update endpoint (PUT/PATCH)
2. Add extra fields to the request body: `"role": "admin"`, `"isAdmin": true`, `"balance": 99999`
3. Check the response and re-fetch the object
4. Mass assignment confirmed if the extra fields were applied

## Remediation Checklist

- [ ] Define explicit Pydantic/Marshmallow/Joi schemas for every input
- [ ] Never use `Object.assign(model, req.body)` or equivalent
- [ ] Sensitive fields (`role`, `isAdmin`, `balance`, `verified`) must only be changed via admin-only endpoints
- [ ] Add integration tests that verify extra fields are rejected


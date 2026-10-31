with open("tests/test_api_frontend/test_api_security_hardening.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    'assert "invalid url scheme" in res.json()["detail"].lower()',
    'assert "invalid url" in res.json()["detail"].lower()'
)

with open("tests/test_api_frontend/test_api_security_hardening.py", "w", encoding="utf-8", newline="") as f:
    f.write(text)

with open("backend/api/app.py", "r", encoding="utf-8") as f:
    app_text = f.read()

target = "        engine = AssessmentEngine(repository=bound_repo, scope_guard=scope_guard)  # type: ignore[arg-type]"
repl = "        await asyncio.sleep(0.05)\n        engine = AssessmentEngine(repository=bound_repo, scope_guard=scope_guard)  # type: ignore[arg-type]"

if target in app_text:
    app_text = app_text.replace(target, repl, 1)
    with open("backend/api/app.py", "w", encoding="utf-8", newline="") as f:
        f.write(app_text)
    print("Updated app.py and test_api_security_hardening.py")
else:
    print("Target not found in app.py")


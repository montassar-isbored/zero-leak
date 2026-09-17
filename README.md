# zero-leak 🛡️

A zero-dependency Git pre-commit hook that prevents committing unhashed PII, ephemeral session tokens (JWTs), and high-entropy private keys.

It inspects only your staged diffs (`git diff --cached`) using pure Python standard libraries.

---

## What It Detects

* **Ephemeral JWTs:** Decodes base64url payloads to expose unexpired claims (`iss`, `exp`).
* **Unhashed PII:** Flags raw email addresses outside test domains (`@example.com`, `@test.com`, `@mock.internal`).
* **Private Keys & Seeds:** Flags 64-character hexadecimal keys with Shannon entropy $\ge 3.5$.

---

##  Usage
### 1. Manual Scan
Run inside any Git repository with staged files:
```bash
git add .
python3 path/to/zero_leak.py
```

### 2. Auto-block commits with Git Hook
```bash
echo "python3 $(pwd)/zero_leak.py --hook" >> .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### 3. Pre-commit Framework
Add the following to your `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/montassar-isbored/zero-leak
    rev: v0.1.0
    hooks:
      - id: zero-leak
```

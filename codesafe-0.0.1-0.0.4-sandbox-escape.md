# CodeSafe - safe_eval sandbox escape

Indirect calls through subscript expressions can bypass the checks applied to direct calls in safe_eval. An attacker who controls an evaluated expression can execute Python code with the host application's permissions.

- **Advisory:** GHSA-7gp8-3j6q-v4h8
- **Published:** 2026-09-20
- **Affected:** 0.0.1-0.0.4
- **Patched:** 0.0.5
- **Credit:** @hkmj19 - Reporter

[Official advisory and full details](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8)

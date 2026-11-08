# Open-source vulnerability research

Short notes on my publicly disclosed vulnerability research, with links to the maintainers' advisories for full details. I add entries as new disclosures become public.

Researcher: [Hemanth Kumar M J (@hkmj19)](https://github.com/hkmj19)

## Published advisories

| Published | Project | Finding | Note |
| --- | --- | --- | --- |
| 2026-10-28 | @hapi/inert | Route authentication bypass through encoded path separators | [GHSA-3g2c-3cj7-93hf](hapi-inert-before-7.1.3-auth-bypass.md) |
| 2026-10-20 | samlify | SAML signing-certificate trust bypass with RSAKeyValue metadata | [GHSA-w8r9-gp23-wcxp](samlify-before-2.15.0-cert-trust-bypass.md) |
| 2026-10-14 | sanitize-html | Unbounded recursion while processing discarded iframe content | [GHSA-c9rx-x947-fp3h](sanitize-html-2.18.0-recursion-dos.md) |
| 2026-09-20 | CodeSafe | safe_eval sandbox escape through indirect calls | [GHSA-7gp8-3j6q-v4h8](codesafe-0.0.1-0.0.4-sandbox-escape.md) |
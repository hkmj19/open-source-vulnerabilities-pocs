# @hapi/inert - route authentication bypass

Encoded path separators can cause a public directory handler to serve a file that a more specific route protects with authentication. This affects configurations where those handlers expose the same directory.

- **Advisory:** GHSA-3g2c-3cj7-93hf
- **Published:** 2026-10-28
- **Affected:** versions before 7.1.3
- **Patched:** 7.1.3
- **Credit:** @hkmj19 - Finder

[Official advisory and full details](https://github.com/hapijs/inert/security/advisories/GHSA-3g2c-3cj7-93hf)

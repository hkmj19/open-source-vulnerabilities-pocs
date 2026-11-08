# sanitize-html - unbounded recursion

Re-sanitizing the content of discarded iframes can recurse without a bound, causing a stack overflow on crafted input. The same code path can also bypass the configured nesting limit.

- **Advisory:** GHSA-c9rx-x947-fp3h
- **Published:** 2026-10-14
- **Affected:** >= 2.18.0, < 2.18.1
- **Patched:** 2.18.1
- **Credit:** @hkmj19 - Reporter

[Official advisory and full details](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-c9rx-x947-fp3h)

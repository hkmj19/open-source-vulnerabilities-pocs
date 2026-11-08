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

## Reference awaiting verification

- [serve-static: GHSA-v7hm-xjw3-9w6c](serve-static-version-unverified-advisory-pending.md) - the supplied advisory URL returned 404 when checked on 2026-11-09. Details and credit are not yet verified.

## Other research notes

- [SlowAPI rate-limit bypass write-up](slowapi-rate-limit-bypass.md) - existing research note, listed separately from the maintainer-published advisories above.

## Adding a finding

Name files as `package-affected-version-short-vulnerability.md`. Use `before-VERSION` for an affected range with an exclusive upper bound; do not use the fixed version as if it were vulnerable.

Copy [TEMPLATE.md](TEMPLATE.md), add a brief summary and the official public advisory link, then add a row to this index. Use one file per distinct advisory. Private reports and unpublished details are not included here.

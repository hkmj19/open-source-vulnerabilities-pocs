# samlify - signing-certificate trust bypass

When identity-provider metadata uses RSAKeyValue instead of an X.509 certificate, the verification path can trust a certificate supplied in an attacker-controlled SAML response. This can allow forged login responses to be accepted.

- **Advisory:** GHSA-w8r9-gp23-wcxp
- **Published:** 2026-10-20
- **Affected:** versions before 2.15.0
- **Patched:** 2.15.0
- **Credit:** @hkmj19 - Reporter

[Official advisory and full details](https://github.com/tngan/samlify/security/advisories/GHSA-w8r9-gp23-wcxp)

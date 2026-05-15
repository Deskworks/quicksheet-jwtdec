# quicksheet-jwtdec

JWT token decoder extension for [QuickSheet](https://github.com/cemheren/QuickSheet) — paste a token, see header & claims instantly. **Tokens never leave your machine.**

## Why?

Every dev debugging auth ends up on [jwt.io](https://jwt.io). That means pasting potentially-sensitive tokens into a third-party website. This extension decodes JWTs **100% locally** — zero network calls, zero data leaving your machine.

## What you get

```
🔑 JWT DECODE    │ VALUE
── HEADER ──     │
alg              │ RS256
typ              │ JWT
── CLAIMS ──     │
sub              │ 1234567890  (subject)
name             │ John Doe
admin            │ true
iat              │ 1516239022  (2018-01-18 01:30:22 UTC)
exp              │ 1716239022  (2024-05-20 21:03:42 UTC ⚠ EXPIRED)
── SIGNATURE ──  │ Present (256 chars)
```

Features:
- 🔑 **Header + payload decoding** — algorithm, type, all claims
- ⏳ **Smart timestamp annotations** — `exp`, `iat`, `nbf` shown as human dates with expiry countdown
- ⚠️ **Expiration warnings** — instantly see if a token is expired
- 🏷️ **Claim annotations** — well-known claims (iss, sub, aud, etc.) labeled with meaning
- 🔒 **Privacy-first** — zero network calls, runs entirely on your machine
- 📋 **Handles any JWT** — HS256, RS256, ES256, unsigned — if it's base64url, it decodes

## Install

In any QuickSheet cell:
```
ext: github:cemheren/quicksheet-jwtdec
```

## Usage

```
jwtdec: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM...
```

Paste the full token (header.payload.signature) and the extension decodes it into a readable grid.

## Requirements

- [QuickSheet](https://github.com/cemheren/QuickSheet) v0.6.0+
- .NET 9 SDK

## Protocol

Uses QuickSheet's JSON-lines v1 extension protocol. Emits `{r, c, v}` cell format.

## License

MIT

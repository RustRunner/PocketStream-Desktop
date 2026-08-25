# G1-R SRT/OpenSSL security review — 2026-08-25

This review applies only to the hash-identified G1-R runtime:

- `libsrt.dll` 1.5.6 — SHA-256
  `45d2508afcd922f64124671965a1dabf02bca2bcc295d8c82f70c4653aaeab30`
- `libcrypto-3-x64.dll` 3.5.0 — SHA-256
  `8a0e2418a3106c814a2c117c591750f34c0c1b9bef23d2e95dd36c61558e37e0`
- official GStreamer 1.26.11 MSVC x86_64 runtime MSI — SHA-256
  `31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605`

## SRT result

SRT 1.5.6 is the patched version for both critical 2026 advisories that
invalidate the stock 1.5.4 runtime:

- [CVE-2026-55869 / GHSA-6xg9-784j-24rm](https://github.com/Haivision/srt/security/advisories/GHSA-6xg9-784j-24rm)
  affects versions through 1.5.5 and identifies 1.5.6 as patched.
- [CVE-2026-55868 / GHSA-4mc6-qmpp-g7gw](https://github.com/Haivision/srt/security/advisories/GHSA-4mc6-qmpp-g7gw)
  affects versions through 1.5.5 and identifies 1.5.6 as patched.
- The [SRT 1.5.6 release](https://github.com/Haivision/srt/releases/tag/v1.5.6)
  explicitly identifies both fixes and their related hardening changes.

Result: SRT 1.5.6 meets the specification's SRT security floor. Network
restriction through a VPN remains useful defense in depth, but is not treated
as a substitute for the patched library.

## OpenSSL finding and reachability

The official GStreamer 1.26.11 MSI supplies OpenSSL 3.5.0. It is no longer the
current 3.5 patch: upstream released OpenSSL 3.5.8 on this review date, and the
[3.5 release notes](https://openssl-library.org/news/openssl-3.5-notes/)
identify cumulative security fixes in 3.5.1 through 3.5.8. The complete
[OpenSSL 3.5 vulnerability list](https://openssl-library.org/news/vulnerabilities-3.5/)
therefore applies at the component-version level to 3.5.0.

The staged bundle's PE import tables show that `libsrt.dll` is the only bundled
consumer of `libcrypto-3-x64.dll`. Review of pinned SRT 1.5.6's
`haicrypt/cryspr-openssl-evp.c` shows this reachable API surface:

- `RAND_bytes`;
- AES ECB/CTR/GCM through `EVP_CipherInit_ex`, `EVP_CipherUpdate`,
  `EVP_CipherFinal_ex`, and GCM tag controls;
- `PKCS5_PBKDF2_HMAC_SHA1`; and
- RFC 3394-style `AES_wrap_key` / `AES_unwrap_key`.

The published fixes reviewed through 3.5.8 concern TLS/DTLS/QUIC, X.509,
ASN.1, CMP/CRMF, CMS/PKCS#7/PKCS#12, HTTP, command-line utilities, SM2,
AES-OCB, AES-SIV/GCM-SIV, or the one-shot `EVP_Cipher()` path. PocketStream's
SRT path exposes none of those protocols or formats and uses the documented
streaming cipher interface, not `EVP_Cipher()`. No reviewed advisory describes
the AES CTR/GCM, PBKDF2, random-generation, or RFC 3394 key-wrap use exercised
by this gate.

## Decision and residual risk

This is a scoped reachability finding, not a claim that OpenSSL 3.5.0 is
generally current or vulnerability-free. G1-R may pass for the exact prescribed
GStreamer 1.26.11/SRT transport closure because the approved recipe changes
only SRT and the known OpenSSL findings reviewed here are outside the sole
reachable consumer path.

G3 remains release-blocking and must repeat the advisory scan. An OpenSSL 3.5.8
uplift should be evaluated as a separate pinned dependency change with ABI,
closure, encryption, and clean-install revalidation; it must not be silently
substituted into this hash-identified G1-R artifact.

# G3 final-closure security review — 2026-08-25

This review repeats the upstream advisory scan for the exact native libraries
locked into the final PocketStream bundle:

- `libsrt.dll` 1.5.6 — SHA-256
  `45d2508afcd922f64124671965a1dabf02bca2bcc295d8c82f70c4653aaeab30`;
- `libcrypto-3-x64.dll` 3.5.0 — SHA-256
  `8a0e2418a3106c814a2c117c591750f34c0c1b9bef23d2e95dd36c61558e37e0`;
- official GStreamer 1.26.11 MSVC x86_64 runtime MSI — SHA-256
  `31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605`.

The review expires after 30 days. A release after 2026-09-24 must repeat the
scan and update the hash-pinned review record even if no binary changes.

## SRT result

The two critical network-reachable issues that invalidate stock SRT 1.5.4 are
fixed by the staged 1.5.6 runtime:

- [CVE-2026-55869 / GHSA-6xg9-784j-24rm](https://github.com/Haivision/srt/security/advisories/GHSA-6xg9-784j-24rm)
  lists 1.5.6 as the patched version for the KMREQ/KMRSP buffer overflow.
- [CVE-2026-55868 / GHSA-4mc6-qmpp-g7gw](https://github.com/Haivision/srt/security/advisories/GHSA-4mc6-qmpp-g7gw)
  lists 1.5.6 as the patched version for the encryption-state downgrade.
- The [SRT 1.5.6 release](https://github.com/Haivision/srt/releases/tag/v1.5.6)
  records both fixes.

Result: SRT 1.5.6 meets PocketStream's security floor. A private VPN remains
defense in depth and is not used as a substitute for the patched library.

## OpenSSL finding and reachability

The pinned GStreamer MSI supplies OpenSSL 3.5.0. It is not a current 3.5 patch
release: [OpenSSL 3.5 release notes](https://openssl-library.org/news/openssl-3.5-notes/)
record security fixes through 3.5.8, and the complete
[OpenSSL 3.5 vulnerability list](https://openssl-library.org/news/vulnerabilities-3.5/)
therefore reports 3.5.0 as affected at the component-version level.

The locked bundle import tables identify `libsrt.dll` as the only shipped
consumer of `libcrypto-3-x64.dll`. Pinned SRT 1.5.6 reaches only this OpenSSL
surface in `haicrypt/cryspr-openssl-evp.c`:

- `RAND_bytes`;
- AES ECB/CTR/GCM through the streaming `EVP_CipherInit_ex`,
  `EVP_CipherUpdate`, and `EVP_CipherFinal_ex` interfaces plus GCM controls;
- `PKCS5_PBKDF2_HMAC_SHA1`; and
- RFC 3394-style `AES_wrap_key` and `AES_unwrap_key`.

The upstream fixes reviewed through 3.5.8 concern TLS, DTLS, QUIC, X.509,
ASN.1, CMP/CRMF, CMS/PKCS#7/PKCS#12, HTTP, command-line utilities, SM2,
AES-OCB, AES-SIV/GCM-SIV, or the one-shot `EVP_Cipher()` path. PocketStream's
SRT transport accepts none of those protocols or formats and does not call the
one-shot cipher API. No reviewed advisory reaches the AES CTR/GCM, PBKDF2,
random-generation, or RFC 3394 key-wrap operations used here.

## Decision and residual risk

G3 accepts this exact OpenSSL 3.5.0 DLL only for the narrow, hash-identified
SRT consumer path above. This is not a claim that OpenSSL 3.5.0 is generally
current or vulnerability-free. Any new consumer of `libcrypto-3-x64.dll`, any
new advisory reaching that surface, or expiration of this review blocks the
release.

An OpenSSL uplift remains a separate pinned dependency change. It requires a
new full-bundle lock plus SRT ABI, encryption, closure, G1-R/G2, and installed
package revalidation; release automation must never substitute a newer DLL
silently.

# G3 native-library security review - 2026-10-23

This review supersedes the August review for the following exact files:

- SRT 1.5.7 `libsrt.dll`: SHA256
  `8d58764b2d53df76b7e9b69e55cd3250d3bb0c14631224c0f16962c5317a5600`.
- OpenSSL 3.5.0 `libcrypto-3-x64.dll`: SHA256
  `8a0e2418a3106c814a2c117c591750f34c0c1b9bef23d2e95dd36c61558e37e0`.
- GStreamer 1.26.11 runtime MSI: SHA256
  `31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605`.

The manifest retains its 30-day review expiry. Behavioral qualification and
installed-package verification are separate required gates; this record alone
does not declare the application ready for publication.

## SRT decision

[GHSA-m96h-3rc9-xx6h](https://github.com/Haivision/srt/security/advisories/GHSA-m96h-3rc9-xx6h)
identifies a critical pre-authentication handshake heap overflow affecting
versions through 1.5.6, fixed in 1.5.7. Accordingly, the previous SRT 1.5.6
security decision is no longer acceptable for a new release.

The selected [SRT 1.5.7 release](https://github.com/Haivision/srt/releases/tag/v1.5.7)
also retains and hardens the fixes for
[CVE-2026-55869](https://github.com/Haivision/srt/security/advisories/GHSA-6xg9-784j-24rm)
and [CVE-2026-55868](https://github.com/Haivision/srt/security/advisories/GHSA-4mc6-qmpp-g7gw).
The upstream advisory list was checked on the review date. The new DLL was
built from archive SHA256
`017cd1e437ef2073a4dd10ddf7b55e86bc3d6ebac0393d13bd22f6a57055d32b`
using the pinned Cerbero commit and GCC 14.2.0 compiler. Its embedded runtime
version is `0x010507`; its import table matches the stock GStreamer SRT ABI.

## OpenSSL scope

The [OpenSSL 3.5 vulnerability list](https://openssl-library.org/news/vulnerabilities-3.5/)
and [3.5 release notes](https://openssl-library.org/news/openssl-3.5-notes/)
were reviewed through 3.5.9. The September additions concern X.509 CRL
processing, QUIC, DTLS/TLS, elliptic-curve/SM2 operations, CMP, and AES-SIV.
OpenSSL 3.5.0 remains affected at the general component-version level.

Inspection of the pinned SRT 1.5.7 `haicrypt/cryspr-openssl-evp.c` confirms
the same limited consumer surface as the prior review: RAND_bytes,
AES ECB/CTR/GCM through streaming EVP operations, PBKDF2-HMAC-SHA1, and
AES key wrapping. It does not select SIV/OCB/GCM-SIV, use the one-shot
EVP_Cipher API, parse certificates, or implement OpenSSL TLS/DTLS/QUIC.
G3 independently checks that SRT is the only bundled libcrypto consumer.

The reviewed advisories therefore do not reach this consumer surface. This
is a scoped reachability assessment, not a claim that OpenSSL 3.5.0 is
generally current or free of vulnerabilities. Accept this exact DLL only
with the inspected consumer and the full closure checks. A changed consumer,
new applicable advisory, changed binary, or expired review requires a new
decision. An OpenSSL upgrade remains a separate dependency qualification.

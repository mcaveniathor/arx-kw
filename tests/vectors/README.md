# Envelope v1 compatibility vectors

`envelope-v1.tsv` freezes the bytes emitted by the **published arx-kw 0.4.0**
crate, downloaded from crates.io and verified with SHA-256:

```text
275d023cad5d923a966911da1ab5f91453d992f734d1a6701b22907430ab504e
```

Each tab-separated row contains variant, wrapping key hex, plaintext hex,
context hex, and complete envelope hex. Empty fields are significant.
Keys are consecutive bytes starting at zero (48 bytes for E/EX, 32 for G/GX).
Plaintext byte `i` is `(7*i + 3) mod 256`, at lengths 0, 1, 32, and 64.
Contexts are empty for length 0, `00ff80` for length 1, and UTF-8
`example.com/tenant/42/key-storage/v1` otherwise.

All sixteen records were encrypted and decrypted with the checksum-verified
0.4.0 package, then checked against this release. These are compatibility
fixtures, not an independent cryptographic oracle. Do not regenerate expected
outputs from the implementation under test. Intentional format changes require a
new envelope version; preserve these v1 fixtures.

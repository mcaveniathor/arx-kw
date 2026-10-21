---
name: "arx-kw-38682d14-guide"
description: "Use arx-kw 0.5.0 for the tasks covered in its release guidance; consult cited findings, recipe verification status, and required features."
depends-on: "arx-kw==0.5.0"
---

# arx-kw 0.5.0

Release-specific guidance for arx-kw 0.5.0: context-bound data-key wrapping, wrapping-key rotation, and detached-tag storage. Recipes use minimal features and OS-generated keys. Imported structured analysis based on the frozen published crate; no separate review is recorded. The guide covers these three tasks, not the entire API.

Use this guidance only with the stated release. Check the project's Cargo.lock before applying it. A compiled recipe passed cargo check; runtime behavior has not been tested. Read each recipe's feature and dependency requirements.

## Guidance

- [Bind a data key to a stable application context](references/findings/context-wrapping.md) — Documented.
- [Select only the required variant and envelope features](references/findings/minimal-features.md) — Documented.
- [Keep owned keys and recovered plaintext in erasing guards](references/findings/secret-ownership.md) — Documented.
- [Authenticate before rotating a wrapping key](references/findings/rotation.md) — Documented.
- [Use dedicated keys with raw detached storage](references/findings/detached-storage.md) — Documented.
- [Use deterministic wrapping for high-entropy key material](references/findings/security-boundaries.md) — Documented.

## Recipes

- [Wrap a data key for a tenant](references/recipes/wrap-key.md) — Compiled.
- [Rotate a wrapping key](references/recipes/rotate-key.md) — Compiled.
- [Store ciphertext and tag separately](references/recipes/detached-tag.md) — Compiled.

## Documentation examples

8 examples inventoried. [Adaptations, supporting examples, and skipped examples with reasons](references/examples.md); [complete inventory and coverage data](references/examples.json). This accounts only for the collected evidence.

## Coverage limitations

- Collection is bounded to 48 UTF-8 evidence files, 48 KiB per file, and 320 KiB total; examples and API documentation are sampled, not exhaustive. Rendered documentation and external documentation sites are not crawled.
- Pinned repository archive: 1 link or special-file entries were rejected without following or extracting them.

## Provenance

[Release, evidence hashes, review status, and compilation records](references/provenance.json). Paths in that record are relative to its directory. Dependency lockfiles are included alongside the records.

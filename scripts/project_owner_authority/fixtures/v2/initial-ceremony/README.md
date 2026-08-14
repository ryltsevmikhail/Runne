# Initial authorization dry-run fixture

This directory is a deterministic, non-authoritative test vector.  Its fake
key and fake RNG seed are test-only constants; it does not represent a
Keychain item, a production signature, or an approved ceremony.

`subject-s.json` names the signed subject commit S. The four files in `blobs/`
are the exact regular blobs bound by canonical-LF `receipt-s.json`, generated
and verified with the real v2 receipt core and a fixed test-only Ed25519 key.
The Python test constructs raw Git SHA-1 blob/tree/commit bytes in memory; it
does not invoke Git or write an object database. `evidence-e.json` names a
distinct receipt-containing commit E and binds the SHA-256 of the raw receipt
bytes. The receipt path is deliberately outside the closed four-document
profile, so the receipt never binds itself.

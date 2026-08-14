# Fixture-only reconciliation vector

`initial-receipt.json` is the byte-identical Task 13 canonical receipt. `documents/`
contains 28 deterministic raw blobs matching the closed v3 profile. S2 binds only
those blobs; E2 preserves every S2 blob and adds the initial and S2 receipt paths.
Both commits are derived in memory and remain test-only, never production authority.

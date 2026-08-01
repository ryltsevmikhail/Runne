#!/usr/bin/env python3
"""GOCODE Runtime L3 Golden Migration Artifact Verifier.

The implementation lives in verify_migration_artifacts_impl modules; this
facade preserves the historical script path and test-facing helper names.
"""

import os
import sys

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, SCRIPT_DIRECTORY)

from verify_migration_artifacts_impl.checks import check_blacklist, check_source_sha
from verify_migration_artifacts_impl.constants import (
    BASE,
    BASELINE_SHA,
    BLACKLIST_KEYS,
    DIGEST_RE,
    GOLDEN_DIR,
    SCHEMA_PATH,
    SHA_RE,
    errors,
    warnings,
)
from verify_migration_artifacts_impl.io import (
    compute_digest,
    display_path,
    jcs_canonicalize,
    load_json,
    parse_args,
    verify_digest_sidecar,
)
from verify_migration_artifacts_impl.main import main, print_summary
from verify_migration_artifacts_impl.schema import (
    validate_against_schema,
    validate_type,
)


if __name__ == "__main__":
    sys.exit(main())

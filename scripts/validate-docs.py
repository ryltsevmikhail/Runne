#!/usr/bin/env python3
"""Run the repository documentation validator."""

from pathlib import Path

exec((Path(__file__).with_name("validate_docs_impl.inc")).read_text(encoding="utf-8"))

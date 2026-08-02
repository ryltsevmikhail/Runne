#!/usr/bin/env python3
"""Validate repository dependency boundaries."""

from pathlib import Path


exec(
    (Path(__file__).with_name("validate_architecture_impl.inc")).read_text(
        encoding="utf-8"
    )
)

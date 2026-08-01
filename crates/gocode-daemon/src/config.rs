//! Daemon configuration subsystem.
//!
//! Implements ADR-0014 bootstrap subset:
//! - `BuiltInDefaults` — mandatory defaults.
//! - `SystemConfig` — optional TOML overrides on top of defaults.
//! - `ConfigurationSnapshot` — immutable merge result with provenance and
//!   deterministic digest (SHA-256 of canonical JSON).

use crate::error::DaemonError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

include!("config/merge.rs");
include!("config/helpers.rs");
include!("config/load.rs");

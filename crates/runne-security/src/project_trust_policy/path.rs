//! T1 frozen path policy (inventory §G3, policy revision 2): normalization,
//! the frozen deny set, and its comparison semantics.

use unicode_normalization::UnicodeNormalization;

/// Path components rejected before deny comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    /// Absolute path or rooted component.
    Absolute,
    /// Parent traversal component.
    ParentTraversal,
    /// Home shorthand or shell-ish prefix.
    HomePrefix,
    /// Empty component (double separator or trailing separator).
    EmptyComponent,
    /// Backslash is ambiguous across platforms.
    Backslash,
    /// Control characters are never legitimate in a source path.
    ControlCharacter,
    /// Reserved characters rejected cross-platform (F5: Windows drive
    /// letters and NTFS ADS colons are unsupported path forms).
    ReservedCharacter,
    /// Revision 2: Win32 path normalization silently strips trailing dots
    /// and spaces, so such a component opens a different file on Windows
    /// than the one admitted on POSIX. Ambiguous shapes are rejected,
    /// never repaired (F5).
    TrailingReservedSuffix,
}

/// Frozen component deny set (inventory §G3, policy revision 2). Revision 2
/// adds the remaining OpenSSH default key names, `.git-credentials`, and the
/// dotenv family prefix (see [`FROZEN_DENY_PREFIXES`]).
pub const FROZEN_DENY_COMPONENTS: [&str; 13] = [
    ".git",
    ".ssh",
    ".aws",
    ".env",
    ".netrc",
    ".npmrc",
    ".git-credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ed25519_sk",
    "credentials.json",
];

/// Frozen suffix deny set (inventory §G3).
pub const FROZEN_DENY_SUFFIXES: [&str; 5] = [".key", ".pem", ".p12", ".ppk", ".gpg"];

/// Revision 2: component prefixes denied wholesale (dotenv family:
/// `.env.local`, `.env.production`, ...). The exact `.env` component stays in
/// [`FROZEN_DENY_COMPONENTS`]; `environment.md` is not affected.
pub const FROZEN_DENY_PREFIXES: [&str; 1] = [".env."];

/// NFC-normalizes and validates a workspace-relative path.
///
/// Returns the normalized components. Ambiguous and unsupported shapes are
/// rejected, never repaired: absolute paths, `..`, `~`, backslashes, empty
/// components, control characters, reserved `:` and trailing dots/spaces all
/// fail closed.
pub fn normalize_source_path(raw: &str) -> Result<Vec<String>, PathRejection> {
    if raw.starts_with('/') {
        return Err(PathRejection::Absolute);
    }
    if raw.contains('\\') {
        return Err(PathRejection::Backslash);
    }
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(PathRejection::ControlCharacter);
    }
    if raw.is_empty() {
        return Err(PathRejection::EmptyComponent);
    }
    let mut components = Vec::new();
    for component in raw.split('/') {
        if component.is_empty() {
            return Err(PathRejection::EmptyComponent);
        }
        if component == "." {
            return Err(PathRejection::EmptyComponent);
        }
        if component == ".." {
            return Err(PathRejection::ParentTraversal);
        }
        if component.starts_with('~') {
            return Err(PathRejection::HomePrefix);
        }
        if component.contains(':') {
            return Err(PathRejection::ReservedCharacter);
        }
        let normalized: String = component.nfc().collect();
        if normalized.starts_with('/') {
            return Err(PathRejection::Absolute);
        }
        if normalized.ends_with('.') || normalized.ends_with(' ') {
            return Err(PathRejection::TrailingReservedSuffix);
        }
        components.push(normalized);
    }
    Ok(components)
}

/// ASCII case-insensitive fold of a whole string (deny names are all-ASCII).
fn ascii_fold(value: &str) -> String {
    value
        .chars()
        .map(|char| char.to_ascii_lowercase())
        .collect()
}

/// Comparison keys for one normalized component.
///
/// Revision 2 closes the Unicode case-mapping collision families: platform
/// openers fold case with full Unicode mappings (NT `OBJ_CASE_INSENSITIVE`
/// upcase table, APFS case-insensitive volumes), while the pre-revision
/// comparison folded ASCII bytes only, so e.g. `ıd_rsa` (U+0131 → `I`) or a
/// long-s `id_rſa` (U+017F → `S`, confirmed on APFS) passed admission and
/// still opened the denied file; a KELVIN `.key` form is absorbed by NFC
/// composition before the fold even runs.
/// The keys over-approximate every case-mapped form; over-deny is the safe
/// direction, and characters whose mappings never reach ASCII (İ, Cyrillic)
/// keep their exact names admissible.
fn fold_keys(component: &str) -> [String; 3] {
    let upper: String = component.chars().flat_map(char::to_uppercase).collect();
    let lower: String = component.chars().flat_map(char::to_lowercase).collect();
    [
        ascii_fold(component),
        ascii_fold(&upper),
        ascii_fold(&lower),
    ]
}

/// Whether normalized components match the frozen deny set (§G3, revision 2).
pub fn denied_by_frozen_set(components: &[String]) -> bool {
    components.iter().any(|component| {
        fold_keys(component).iter().any(|key| {
            FROZEN_DENY_COMPONENTS.iter().any(|denied| key == denied)
                || FROZEN_DENY_PREFIXES
                    .iter()
                    .any(|prefix| key.starts_with(prefix))
                || FROZEN_DENY_SUFFIXES
                    .iter()
                    .any(|suffix| key.ends_with(suffix))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_case_mapped_deny_collisions_are_denied() {
        // NT UPCASE maps U+0131 to ASCII I; the uppercase key reaches id_rsa.
        assert!(denied_by_frozen_set(&["ıd_rsa".to_string()]));
        let nested = normalize_source_path("keys/ıD_RSA").expect("normalizes");
        assert!(denied_by_frozen_set(&nested));
        // KELVIN SIGN reaches K via NFC compatibility composition and via
        // both case-mapped keys.
        assert!(denied_by_frozen_set(&["host.\u{212A}ey".to_string()]));
        assert!(denied_by_frozen_set(&[".\u{212A}ey".to_string()]));
        assert!(denied_by_frozen_set(&["HOST.\u{212A}EY".to_string()]));
    }

    #[test]
    fn unicode_names_without_ascii_collision_stay_admissible() {
        // İ never folds to bare ASCII i on NT/APFS; denying it would be a
        // false positive.
        assert!(!denied_by_frozen_set(&["İd_rsa".to_string()]));
        // Legitimate non-ASCII names are unaffected by over-deny.
        assert!(!denied_by_frozen_set(&["заметки.md".to_string()]));
        assert!(!denied_by_frozen_set(&["caf\u{e9}/readme.md".to_string()]));
        // Non-denied files in the same families stay admissible.
        assert!(!denied_by_frozen_set(&["identity.md".to_string()]));
        assert!(!denied_by_frozen_set(&["environment.md".to_string()]));
        assert!(!denied_by_frozen_set(&["notes.key.txt".to_string()]));
        assert!(!denied_by_frozen_set(&[".gitmodules".to_string()]));
    }

    #[test]
    fn revision_two_deny_set_additions_are_denied() {
        for denied in [
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "id_ed25519_sk",
            ".git-credentials",
            ".env.local",
            ".env.production",
            "config/.env.development",
        ] {
            let components = normalize_source_path(denied).expect("normalizes");
            assert!(denied_by_frozen_set(&components), "{denied} must be denied");
        }
    }

    #[test]
    fn trailing_dots_and_spaces_are_rejected_not_repaired() {
        assert_eq!(
            normalize_source_path("host.key."),
            Err(PathRejection::TrailingReservedSuffix)
        );
        assert_eq!(
            normalize_source_path("id_rsa "),
            Err(PathRejection::TrailingReservedSuffix)
        );
        assert_eq!(
            normalize_source_path("docs/plan. /x"),
            Err(PathRejection::TrailingReservedSuffix)
        );
        assert!(normalize_source_path("plan .md").is_ok());
        assert!(normalize_source_path("v1.2/notes.md").is_ok());
    }
}

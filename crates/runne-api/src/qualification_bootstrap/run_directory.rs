use sha2::{Digest as _, Sha256};

use super::RunBinding;

impl RunBinding {
    /// Derives a case-stable directory component from the exact validated run ID.
    ///
    /// This is a path component, not admission or authority. The fixed parent
    /// directory and filesystem checks remain the native host's responsibility.
    #[must_use]
    pub fn qualification_directory_name(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"runne/qualification/run-directory/v1\0");
        digest.update(self.workflow_run_id().as_bytes());
        hex::encode(digest.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::RunBinding;

    fn binding(run: &str) -> RunBinding {
        RunBinding::new(run, [1; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]).unwrap()
    }

    #[test]
    fn case_distinct_run_ids_remain_distinct_on_case_insensitive_filesystems() {
        let upper = binding("Run-42").qualification_directory_name();
        let lower = binding("run-42").qualification_directory_name();
        assert_ne!(upper.to_lowercase(), lower.to_lowercase());
        for name in [upper, lower] {
            assert_eq!(name.len(), 64);
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
        }
    }

    #[test]
    fn directory_name_has_a_stable_domain_separated_commitment() {
        assert_eq!(
            binding("run-42").qualification_directory_name(),
            "517fc184cdbee4d7cedda1d2cc41929a5c5a44874c592dc64be460aff5f792d0"
        );
    }
}

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::issuer::ProducerError;

pub fn publish_json(path: &Path, value: &impl Serialize) -> Result<(), ProducerError> {
    if !path.is_absolute() || path.exists() || path.is_symlink() {
        return Err(ProducerError::Output);
    }
    let parent = path.parent().ok_or(ProducerError::Output)?;
    let parent = parent.canonicalize().map_err(|_| ProducerError::Output)?;
    let name = path
        .file_name()
        .ok_or(ProducerError::Output)?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| ProducerError::Output)?;
        let mut bytes = serde_json::to_vec(value).map_err(|_| ProducerError::Output)?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(|_| ProducerError::Output)?;
        file.sync_all().map_err(|_| ProducerError::Output)?;
        std::fs::hard_link(&temporary, path).map_err(|_| ProducerError::Output)?;
        File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProducerError::Output)
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_create_new_and_canonical() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("metadata.json");
        publish_json(&output, &serde_json::json!({"value": 1})).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"{\"value\":1}\n");
        assert_eq!(
            publish_json(&output, &serde_json::json!({"value": 2})),
            Err(ProducerError::Output)
        );
    }
}

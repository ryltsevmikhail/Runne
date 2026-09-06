use std::fs;
use std::path::{Path, PathBuf};

pub fn collect_sources(root: &Path, paths: &mut Vec<PathBuf>, violations: &mut Vec<String>) {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            violations.push(format!("cannot scan {}: {error}", root.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                violations.push(format!("cannot read source entry: {error}"));
                continue;
            }
        };
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_symlink() => {
                violations.push(format!("source symlink is forbidden: {}", path.display()));
            }
            Ok(kind) if kind.is_dir() => collect_sources(&path, paths, violations),
            Ok(kind) if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") => {
                paths.push(path);
            }
            Ok(_) => {}
            Err(error) => violations.push(format!("cannot inspect {}: {error}", path.display())),
        }
    }
}

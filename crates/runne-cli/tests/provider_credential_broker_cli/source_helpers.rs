use std::path::{Path, PathBuf};

pub fn broker_sources() -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    collect_rust_sources(&root, &mut paths);
    paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).unwrap();
            (path, source)
        })
        .collect()
}

pub fn source_path_ends_with(path: &Path, components: &[&str]) -> bool {
    path.ends_with(components.iter().collect::<PathBuf>())
}

fn collect_rust_sources(directory: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_sources(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}

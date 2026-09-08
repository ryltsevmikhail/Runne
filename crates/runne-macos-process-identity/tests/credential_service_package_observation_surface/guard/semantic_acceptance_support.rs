use std::path::{Path, PathBuf};

struct CompileDirectory(PathBuf);

impl Drop for CompileDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dependency(directory: &Path, name: &str) -> PathBuf {
    let prefix = format!("lib{name}-");
    std::fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rlib")
                && path
                    .file_name()
                    .is_some_and(|file| file.to_string_lossy().starts_with(&prefix))
        })
        .unwrap_or_else(|| panic!("compiled {name} rlib missing"))
}

/// Compile fixtures against real target APIs, without executing native operations.
pub(super) fn assert_compiles(source: &str, name: &str) {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = CompileDirectory(std::env::temp_dir().join(format!(
        "runne-semantic-acceptance-{}-{unique}-{name}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let input = directory.0.join("fixture.rs");
    std::fs::write(&input, source).unwrap();
    let mut compiler = std::process::Command::new("rustc");
    compiler.args(["--crate-type", "rlib", "--edition", "2024"]);
    compiler.arg(&input);
    link_real_target(&mut compiler);
    let result = compiler
        .arg("-o")
        .arg(directory.0.join("fixture.rlib"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{name} fixture failed to compile: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

pub(super) fn link_real_target(compiler: &mut std::process::Command) {
    let executable = std::env::current_exe().unwrap();
    let dependencies = executable.parent().unwrap();
    compiler.arg("-L");
    compiler.arg(format!("dependency={}", dependencies.display()));
    for name in ["runne_macos_process_identity", "runne_api"] {
        compiler.arg("--extern").arg(format!(
            "{name}={}",
            dependency(dependencies, name).display()
        ));
    }
}

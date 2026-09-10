use std::path::{Path, PathBuf};

struct CompileDirectory(PathBuf);

impl Drop for CompileDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Candidate rlibs, newest first (name as the deterministic tie-break). The
/// last cargo graph that built a crate writes its artifacts last, so the
/// newest carrier and newest api rlib belong to the same build as the running
/// test whenever the current `cargo test` invocation rebuilt them; older
/// variants are feature-set leftovers and are probed only as a fallback.
fn rlibs(directory: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rlib")
                && path
                    .file_name()
                    .is_some_and(|file| file.to_string_lossy().starts_with(prefix))
        })
        .map(|path| {
            let modified = path
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            (modified, path)
        })
        .collect();
    found.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    found.into_iter().map(|(_, path)| path).collect()
}

/// Compiling a fixture that passes the real observation type to the real
/// `verify_exact` release argument only succeeds when both extern rlibs come
/// from one cargo build graph; rustc treats a second `runne_api` variant as a
/// distinct crate and rejects the mismatched type.
const PAIR_PROBE: &str = r"
pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
pub use runne_api::VerifiedSignedInstalledReleaseV2 as Release;
pub fn runne_pair_probe(pending: Pending, release: &Release) {
    let _ = pending.verify_exact(release);
}
";

fn pair_compiles(dependencies: &Path, carrier: &Path, api: &Path) -> Result<bool, String> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("runne-pair-probe-{}-{unique}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let source = directory.join("pair_probe.rs");
    std::fs::write(&source, PAIR_PROBE).unwrap();
    let result = std::process::Command::new("rustc")
        .args(["--crate-type", "rlib", "--edition", "2024"])
        .arg(&source)
        .arg("--extern")
        .arg(format!(
            "runne_macos_process_identity={}",
            carrier.display()
        ))
        .arg("--extern")
        .arg(format!("runne_api={}", api.display()))
        .arg("-L")
        .arg(format!("dependency={}", dependencies.display()))
        .arg("-o")
        .arg(directory.join("pair_probe.rlib"))
        .output();
    let _ = std::fs::remove_dir_all(&directory);
    let result =
        result.unwrap_or_else(|error| panic!("cannot spawn rustc for the pair probe: {error}"));
    if result.status.success() {
        return Ok(true);
    }
    Err(String::from_utf8_lossy(&result.stderr).into_owned())
}

/// Resolve the exact rlib pair this test binary must compile fixtures
/// against. CI accumulates several `lib{name}-<hash>.rlib` variants per crate
/// (feature sets differ across steps), and an arbitrary directory pick can
/// pair a carrier rlib with a `runne_api` instance it was not built against.
/// A single candidate per name is used directly; otherwise the one consistent
/// pairing is identified by probe compilation.
fn resolve_pair(dependencies: &Path) -> (PathBuf, PathBuf) {
    let carriers = rlibs(dependencies, "librunne_macos_process_identity-");
    let apis = rlibs(dependencies, "librunne_api-");
    if let ([carrier], [api]) = (carriers.as_slice(), apis.as_slice()) {
        return (carrier.clone(), api.clone());
    }
    assert!(
        !carriers.is_empty() && !apis.is_empty(),
        "compiled rlib missing in {}: {} carrier, {} api candidates",
        dependencies.display(),
        carriers.len(),
        apis.len()
    );
    let mut last_probe_error = String::new();
    for carrier in &carriers {
        for api in &apis {
            match pair_compiles(dependencies, carrier, api) {
                Ok(true) => return (carrier.clone(), api.clone()),
                Ok(false) => {}
                Err(stderr) => last_probe_error = stderr,
            }
        }
    }
    panic!(
        "no consistent rlib pair in {} ({} carrier x {} api candidates); if every probe \
         failed on the same type mismatch, the probe source itself no longer matches \
         the observed surface:\n{}",
        dependencies.display(),
        carriers.len(),
        apis.len(),
        last_probe_error
    );
}

fn linked_pair(dependencies: &Path) -> &'static (PathBuf, PathBuf) {
    static PAIR: std::sync::OnceLock<(PathBuf, PathBuf)> = std::sync::OnceLock::new();
    // Every caller passes current_exe().parent(), so caching over the first
    // captured directory is safe; revisit if a second source directory ever
    // appears.
    PAIR.get_or_init(|| resolve_pair(dependencies))
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
    let (carrier, api) = linked_pair(dependencies);
    compiler.arg("-L");
    compiler.arg(format!("dependency={}", dependencies.display()));
    compiler.arg("--extern").arg(format!(
        "runne_macos_process_identity={}",
        carrier.display()
    ));
    compiler
        .arg("--extern")
        .arg(format!("runne_api={}", api.display()));
}

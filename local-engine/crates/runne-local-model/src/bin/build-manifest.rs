//! `build-manifest` CLI (MANIFEST_TOOLING §Integration): headless path
//! for qualification scripts. Same core as the desktop picker flow;
//! prints canonical manifest bytes and the digest on stdout.

use runne_local_model::{UserSupplied, build_candidate_manifest};
use std::io::BufReader;
use std::process::ExitCode;

struct Args {
    gguf: String,
    user: UserSupplied,
}

fn usage() -> ! {
    eprintln!(
        "usage: build-manifest <gguf-path> --model-id <id> --model-revision <rev> \
         --license <spdx> --source-uri <uri> --publisher <name> --acquired-at <rfc3339> \
         [--template <file>] [--min-runtime <ver>]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let gguf = match it.next() {
        Some(g) => g,
        None => usage(),
    };
    let mut u = UserSupplied::default();
    let mut template: Option<String> = None;
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--model-id" => u.model_id = value(),
            "--model-revision" => u.model_revision = value(),
            "--license" => u.license = Some(value()),
            "--source-uri" => u.provenance_source_uri = Some(value()),
            "--publisher" => u.provenance_publisher = Some(value()),
            "--acquired-at" => u.provenance_acquired_at = Some(value()),
            "--template" => template = Some(value()),
            "--min-runtime" => u.min_compatible_runtime = Some(value()),
            _ => usage(),
        }
    }
    u.chat_template = template.map(|p| std::fs::read(&p).unwrap_or_else(|_| usage()));
    Args { gguf, user: u }
}

fn main() -> ExitCode {
    let args = parse_args();
    let file = match std::fs::File::open(&args.gguf) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("build-manifest: cannot read {}", args.gguf);
            return ExitCode::FAILURE;
        }
    };
    let mut stream = BufReader::new(file);
    match build_candidate_manifest(
        &mut stream,
        &args.user,
        runne_local_model::BUILDER_CONTRACT_VERSION,
    ) {
        Ok(c) => {
            eprintln!("manifest_digest: {}", c.manifest_digest);
            for w in &c.warnings {
                eprintln!("warning: {w}");
            }
            use std::io::Write as _;
            std::io::stdout()
                .write_all(&c.canonical_bytes)
                .expect("stdout");
            println!();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("build-manifest: refused: {e}");
            ExitCode::FAILURE
        }
    }
}

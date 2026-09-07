//! Worker process entrypoint. Phase 1 ships the protocol/engine stack
//! and the strict launch-contract parsing; the actual descriptor
//! inheritance lands with the supervised launch qualification
//! (Phase 6B), because constructing descriptors from inherited numbers
//! requires an unsafe-free path the workspace policy demands we qualify
//! separately. Environment contract (validated here, consumed then):
//! `RUNNE_WORKER_FD`, `RUNNE_WORKER_SECRET_FD`, `RUNNE_WORKER_GEN`,
//! `RUNNE_HOST_GEN`, `RUNNE_BACKEND_PROFILE`.

fn main() {
    #[cfg(feature = "backend-llama-cpp")]
    {
        if let Err(e) = validate_launch_contract() {
            eprintln!("runne-llama-worker: {e}");
            std::process::exit(1);
        }
        eprintln!(
            "runne-llama-worker: launch contract valid; descriptor inheritance \
             lands with the supervised launch qualification (Phase 6B)"
        );
        std::process::exit(2);
    }
    #[cfg(not(feature = "backend-llama-cpp"))]
    {
        eprintln!("runne-llama-worker: build with --features backend-llama-cpp");
        std::process::exit(1);
    }
}

#[cfg(feature = "backend-llama-cpp")]
fn validate_launch_contract() -> Result<(), String> {
    parse_fd("RUNNE_WORKER_FD")?;
    parse_fd("RUNNE_WORKER_SECRET_FD")?;
    parse_gen("RUNNE_WORKER_GEN")?;
    parse_gen("RUNNE_HOST_GEN")?;
    let profile = std::env::var("RUNNE_BACKEND_PROFILE");
    match profile {
        Ok(p) if !p.is_empty() => Ok(()),
        _ => Err("RUNNE_BACKEND_PROFILE: expected non-empty profile id".into()),
    }
}

#[cfg(feature = "backend-llama-cpp")]
fn parse_fd(name: &str) -> Result<i32, String> {
    let v: i32 = std::env::var(name)
        .map_err(|_| format!("{name}: expected descriptor number"))?
        .parse()
        .map_err(|_| format!("{name}: expected descriptor number"))?;
    if v < 3 {
        return Err(format!("{name}: must be an inherited descriptor (>= 3)"));
    }
    Ok(v)
}

#[cfg(feature = "backend-llama-cpp")]
fn parse_gen(name: &str) -> Result<[u8; 16], String> {
    let hex = std::env::var(name).map_err(|_| format!("{name}: expected 32 hex chars"))?;
    if hex.len() != 32 {
        return Err(format!("{name}: expected 32 hex chars"));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("{name}: bad hex"))?;
    }
    Ok(out)
}

//! Produce a qualified Linux V2 tuple from a staged `AppDir` and `AppImage`.
//!
//! Usage: `linux_enrollment_tuple_v2 --app-dir PATH --appimage PATH --receipt PATH \
//! --output PATH --target PATH --qualified-at UNIX --qualification-expires UNIX`

#[cfg(target_os = "linux")]
use runne_platform_desktop::{UpdateTargetV2, produce_linux_native_enrollment_tuple_v2};
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, path::PathBuf, process::ExitCode};

#[cfg(target_os = "linux")]
const FLAGS: [&str; 7] = [
    "--app-dir",
    "--appimage",
    "--receipt",
    "--output",
    "--target",
    "--qualified-at",
    "--qualification-expires",
];

#[cfg(target_os = "linux")]
fn parse_args() -> Result<BTreeMap<String, String>, String> {
    let mut args = std::env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(flag) = args.next() {
        if !FLAGS.contains(&flag.as_str()) {
            return Err(format!("unknown option: {flag}"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if value.starts_with("--") || values.insert(flag.clone(), value).is_some() {
            return Err(format!("invalid or repeated option: {flag}"));
        }
    }
    if FLAGS.iter().any(|flag| !values.contains_key(*flag)) {
        return Err("all seven options are required".into());
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
fn value<'a>(args: &'a BTreeMap<String, String>, flag: &str) -> &'a str {
    args.get(flag).expect("validated required option")
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let args = parse_args()?;
    let target_path = PathBuf::from(value(&args, "--target"));
    let target_bytes =
        std::fs::read(&target_path).map_err(|error| format!("cannot read target JSON: {error}"))?;
    let target: UpdateTargetV2 = serde_json::from_slice(&target_bytes)
        .map_err(|error| format!("invalid strict UpdateTargetV2 JSON: {error}"))?;
    if target.platform != "linux" {
        return Err("target platform must be linux".into());
    }
    let number = |flag| {
        value(&args, flag)
            .parse::<u64>()
            .map_err(|_| format!("{flag} must be an unsigned Unix timestamp"))
    };
    produce_linux_native_enrollment_tuple_v2(
        PathBuf::from(value(&args, "--app-dir")).as_path(),
        PathBuf::from(value(&args, "--appimage")).as_path(),
        PathBuf::from(value(&args, "--receipt")).as_path(),
        PathBuf::from(value(&args, "--output")).as_path(),
        target,
        number("--qualified-at")?,
        number("--qualification-expires")?,
    )
    .map_err(|_| "tuple production rejected the staged inputs or target".to_owned())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linux_enrollment_tuple_v2: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("linux_enrollment_tuple_v2 is supported only on Linux");
    std::process::ExitCode::FAILURE
}

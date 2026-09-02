fn main() {
    println!("cargo:rerun-if-changed=src/native_protocol.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    cc::Build::new()
        .file("src/native_protocol.m")
        .flag("-fblocks")
        .flag("-fobjc-arc")
        .compile("runne_credential_service_xpc_protocol");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

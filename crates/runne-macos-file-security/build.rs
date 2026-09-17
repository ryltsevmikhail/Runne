fn main() {
    println!("cargo:rerun-if-changed=src/acl_presence.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/acl_presence.c")
            .warnings(true)
            .warnings_into_errors(true)
            .compile("runne_macos_file_security");
    }
}

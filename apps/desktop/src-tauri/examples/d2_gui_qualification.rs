#[cfg(target_os = "linux")]
fn main() {
    runne_desktop::run_gui_qualification();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("runne-desktop GUI qualification is Linux-only");
    std::process::exit(1);
}

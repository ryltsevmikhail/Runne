pub(crate) fn record(stage: &'static str, succeeded: bool) {
    #[cfg(target_os = "linux")]
    {
        use std::io::Write as _;
        let outcome = if succeeded { "ok" } else { "failed" };
        let _ = writeln!(
            std::io::stderr().lock(),
            "runne-linux-enrollment stage={stage} outcome={outcome}"
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (stage, succeeded);
}

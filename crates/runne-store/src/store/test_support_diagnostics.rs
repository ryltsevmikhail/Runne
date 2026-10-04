pub(crate) fn record(stage: &'static str) {
    #[cfg(feature = "test-support")]
    eprintln!("runne-store-diagnostic stage={stage}");

    #[cfg(not(feature = "test-support"))]
    let _ = stage;
}

pub(crate) fn on_error<T, E>(stage: &'static str, result: Result<T, E>) -> Result<T, E> {
    if result.is_err() {
        record(stage);
    }
    result
}

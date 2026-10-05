#[test]
fn production_setup_uses_the_anchored_app_core_constructor() {
    let run = include_str!("../src/lib_parts/run.rs");
    let setup = include_str!("../src/lib_parts/setup_app.rs");

    assert!(run.contains(".setup(setup_app)"));
    assert!(setup.contains("AppCore::open_production("));
    assert!(!run.contains("AppCore::open_with_runtime_mode("));
    assert!(!setup.contains("AppCore::open_with_runtime_mode("));
}

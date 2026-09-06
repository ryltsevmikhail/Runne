class NativeQualificationDeliveryAliasTest(unittest.TestCase):
    delivery = Path(
        "apps/desktop/src-tauri/src/provider_credential_enrollment/dispatch.rs"
    )

    def violations(self, payload, relative=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / (relative or self.delivery)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            return architecture.find_native_qualification_admission_surface_violations(root)

    def test_allowed_delivery_files_reject_aliased_forbidden_imports(self):
        cases = (
            ("use std::env; fn load() { env::var(\"TICKET\"); }", None),
            ("use std::fs; fn load() { fs::read(\"ticket\"); }", None),
            ("use std::fs::File as Input; fn load() { Input::open(\"ticket\"); }", None),
            ("use ::std::env as input; fn load() { input::var(\"TICKET\"); }", None),
            ("use r#std::r#fs as input; fn load() { input::read(\"ticket\"); }", None),
            ("use std::{env as x, fs::{self, File as Y}};", None),
            ("use std as platform; fn load() { platform::env::var(\"TICKET\"); }", None),
            ("extern crate std as platform; fn load() { platform::fs::read(\"ticket\"); }", None),
            ("use rusqlite as store; fn load() { store::Connection::open(\"ticket\"); }", None),
            ("use std::path as ticket_path;", None),
            ("use std::fs::OpenOptions as Input; fn load() { Input::new(); }", None),
            ("use {std::env as input};", None),
            ("use {rusqlite as store};", None),
            ("use {::std::fs::OpenOptions as Input};", None),
        )
        for payload, relative in cases:
            with self.subTest(payload=payload):
                self.assertNotEqual([], self.violations(payload, relative))

    def test_delivery_scan_ignores_forbidden_spelling_in_comments_and_literals(self):
        payload = r'''
// std::env::var("TICKET");
/* std::fs::read("ticket"); */
const TEXT: &str = "std::fs::read(ticket)";
const RAW: &str = r#"extern crate std as platform;"#;
'''
        self.assertEqual([], self.violations(payload))

    def test_newly_allowed_production_file_is_automatically_scanned(self):
        relative = Path(
            "crates/runne-daemon/src/protected_activation/control_v3/new_delivery_tests.rs"
        )
        architecture.NATIVE_QUALIFICATION_ADMISSION_ALLOWED.add(relative)
        try:
            self.assertNotEqual(
                [],
                self.violations(
                    "use std::env; fn load() { env::var(\"TICKET\"); }",
                    relative,
                ),
            )
        finally:
            architecture.NATIVE_QUALIFICATION_ADMISSION_ALLOWED.remove(relative)

    def test_exact_known_test_files_remain_excluded(self):
        known_tests = (
            "apps/desktop/src-tauri/src/qualification_ticket_tests.rs",
            "crates/runne-platform-desktop/src/protected_runtime/qualification_relay_tests.rs",
            "crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/tests.rs",
            "crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/connected_tests.rs",
        )
        for relative in known_tests:
            with self.subTest(relative=relative):
                self.assertEqual(
                    [],
                    self.violations("use std::env; env::var(\"TICKET\");", Path(relative)),
                )

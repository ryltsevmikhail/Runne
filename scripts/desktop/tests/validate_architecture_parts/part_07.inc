class MacosXpcAdapterBoundaryTest(unittest.TestCase):
    PACKAGE = "runne-macos-xpc"
    TARGET = 'cfg(target_os = "macos")'

    def test_exact_dependency_shape_is_required(self):
        validate = architecture.find_macos_xpc_dependency_violations
        self.assertEqual([], validate([self.package()], Path("/repo")))
        for label, dependency, field, value in (
            ("extra", None, "append", self.dependency("serde", req="^1")),
            ("wrong target", "objc2", "target", None),
            ("libc must stay macOS-only", "libc", "target", None),
            ("foundation defaults", "objc2-foundation", "uses_default_features", True),
            ("tokio feature drift", "tokio", "features", ["rt"]),
        ):
            with self.subTest(label=label):
                package = self.package()
                if field == "append":
                    package["dependencies"].append(value)
                else:
                    row = next(row for row in package["dependencies"] if row["name"] == dependency)
                    row[field] = value
                self.assertNotEqual([], validate([package], Path("/repo")))
        foreign = self.package()
        foreign["manifest_path"] = f"/tmp/foreign/crates/{self.PACKAGE}/Cargo.toml"
        foreign["dependencies"][0]["path"] = "/tmp/foreign/crates/runne-platform-ports"
        self.assertNotEqual([], validate([foreign], Path("/repo")))
        self.assertNotEqual([], validate([], Path("/repo")))

    def test_native_symbols_and_foundation_types_cannot_escape_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / "crates" / self.PACKAGE
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                '[lints.rust]\nunsafe_code = "allow"\n', encoding="utf-8"
            )
            (crate / "src" / "lib.rs").write_text("pub fn safe() {}\n", encoding="utf-8")
            self.assertEqual([], architecture.find_macos_xpc_source_violations(root))

            foreign = root / "crates" / "foreign" / "src"
            foreign.mkdir(parents=True)
            (foreign / "lib.rs").write_text("struct NSXPCConnection;\n", encoding="utf-8")
            self.assertNotEqual([], architecture.find_macos_xpc_source_violations(root))
            (foreign / "lib.rs").write_text("pub fn safe() {}\n", encoding="utf-8")
            tauri = root / "apps" / "desktop" / "src-tauri" / "src"
            tauri.mkdir(parents=True)
            (tauri / "lib.rs").write_text("struct NSXPCListener;\n", encoding="utf-8")
            self.assertNotEqual([], architecture.find_macos_xpc_source_violations(root))
            (tauri / "lib.rs").write_text("pub fn safe() {}\n", encoding="utf-8")
            (crate / "src" / "lib.rs").write_text(
                "pub fn leaks() -> NSData { todo!() }\n", encoding="utf-8"
            )
            self.assertNotEqual([], architecture.find_macos_xpc_source_violations(root))
            (crate / "src" / "lib.rs").write_text(
                "type Reply = objc2_foundation::NSData;\n"
                "pub(super) fn private() -> Reply { todo!() }\n",
                encoding="utf-8",
            )
            self.assertEqual([], architecture.find_macos_xpc_source_violations(root))
            (crate / "src" / "lib.rs").write_text(
                "pub use objc2_foundation::NSData;\n", encoding="utf-8"
            )
            self.assertNotEqual([], architecture.find_macos_xpc_source_violations(root))
            (crate / "src" / "lib.rs").write_text(
                "pub struct Leak {\n    pub value: objc2_foundation::NSData,\n}\n",
                encoding="utf-8",
            )
            self.assertNotEqual([], architecture.find_macos_xpc_source_violations(root))
            for source in (
                "pub trait Leak { fn data(&self) -> objc2_foundation::NSData; }\n",
                'pub extern "C" fn leak() -> objc2_foundation::NSData { todo!() }\n',
                'pub unsafe extern "C" fn leak(value: NSData) {}\n',
                "use objc2_foundation::NSData as Blob; pub fn leak() -> Blob { todo!() }\n",
                "type Blob = objc2_foundation::NSData; pub fn leak() -> Blob { todo!() }\n",
                (
                    "#[macro_export] macro_rules! expose { () => { pub fn leak() -> "
                    "objc2_foundation::NSData { todo!() } } } expose!();\n"
                ),
                (
                    "macro_rules! expose { ($value:ty) => { pub fn leak() -> "
                    "$value { todo!() } } } expose!(NSData);\n"
                ),
            ):
                with self.subTest(source=source):
                    (crate / "src" / "lib.rs").write_text(source, encoding="utf-8")
                    self.assertNotEqual(
                        [], architecture.find_macos_xpc_source_violations(root)
                    )
            (crate / "src" / "lib.rs").write_text(
                "macro_rules! expose { ($value:ty) => { pub fn leak() -> $value "
                "{ todo!() } } } pub mod child;\n",
                encoding="utf-8",
            )
            (crate / "src" / "child.rs").write_text(
                "expose!(objc2_foundation::NSData);\n", encoding="utf-8"
            )
            self.assertNotEqual([], architecture.find_macos_xpc_source_violations(root))

    @classmethod
    def package(cls):
        mac = cls.TARGET
        registry = architecture.CRATES_IO_REGISTRY_SOURCE
        foundation = ["NSData", "NSError", "NSObject", "NSString", "NSXPCConnection", "block2", "libc", "std"]
        service = ["SMAppService", "objc2", "objc2-foundation", "std"]
        return {
            "name": cls.PACKAGE,
            "manifest_path": f"/repo/crates/{cls.PACKAGE}/Cargo.toml",
            "dependencies": [
                cls.dependency("runne-platform-ports", path="/repo/crates/runne-platform-ports"),
                cls.dependency("rand", req="=0.8.7", source=registry),
                cls.dependency("zeroize", req="=1.9.0", source=registry),
                cls.dependency("block2", req="=0.6.2", target=mac, source=registry),
                cls.dependency("objc2", req="=0.6.4", target=mac, features=["exception"], source=registry),
                cls.dependency("objc2-foundation", req="=0.3.2", target=mac, features=foundation, defaults=False, source=registry),
                cls.dependency("objc2-service-management", req="=0.3.2", target=mac, features=service, defaults=False, source=registry),
                cls.dependency("libc", req="^0.2", target=mac, source=registry),
                cls.dependency("tokio", req="^1", target=mac, features=["full"], source=registry),
                cls.dependency("cc", kind="build", req="=1.4.0", source=registry),
            ],
        }

    @staticmethod
    def dependency(name, *, kind=None, req="*", target=None, features=None, defaults=True, source=None, path=None):
        return {
            "name": name, "kind": kind, "req": req, "features": features or [],
            "optional": False, "rename": None, "target": target,
            "uses_default_features": defaults, "source": source, "path": path,
            "registry": None,
        }

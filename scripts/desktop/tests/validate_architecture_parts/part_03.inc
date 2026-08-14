

class ProtectedAdmissionAdvancedSurfaceTest(unittest.TestCase):
    def test_rejects_valid_const_and_manual_escape_forms(self):
        surfaces = (
            "impl ProtectedRootHandleAdmission { pub const fn encode_token(&self) -> &str { \"\" } }",
            "impl ProtectedRootHandleAdmission { pub const fn admission_bytes(&self) -> &[u8] { &[] } }",
            "impl ProtectedRootHandleAdmission { pub const fn decode_token(&self) -> Self { unreachable!() } }",
            "impl ProtectedRootHandleAdmission { pub const fn admission_string(&self) -> &str { \"\" } }",
            "impl Clone for ProtectedRootHandleAdmission { fn clone(&self) -> Self { unreachable!() } }",
            "impl std::clone::Clone for ProtectedRootHandleAdmission { fn clone(&self) -> Self { unreachable!() } }",
            "use serde::Serialize; impl Serialize for ProtectedRootHandleAdmission { fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> { unreachable!() } }",
            "impl serde::Serialize for ProtectedRootHandleAdmission { fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> { unreachable!() } }",
            "use serde::Deserialize; impl<'de> Deserialize<'de> for ProtectedRootHandleAdmission { fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> { unreachable!() } }",
            "impl<'de> serde::Deserialize<'de> for ProtectedRootHandleAdmission { fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> { unreachable!() } }",
            "impl std::borrow::Borrow<[u8]> for ProtectedRootHandleAdmission { fn borrow(&self) -> &[u8] { unreachable!() } }",
            "use std::borrow::Borrow; impl Borrow<[u8]> for ProtectedRootHandleAdmission { fn borrow(&self) -> &[u8] { unreachable!() } }",
            "use std::borrow::BorrowMut; impl BorrowMut<[u8]> for ProtectedRootHandleAdmission { fn borrow_mut(&mut self) -> &mut [u8] { unreachable!() } }",
            "impl std::borrow::BorrowMut<[u8]> for ProtectedRootHandleAdmission { fn borrow_mut(&mut self) -> &mut [u8] { unreachable!() } }",
        )
        for surface in surfaces:
            with self.subTest(surface=surface), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    "pub struct ProtectedRootHandleAdmission {}\n" + surface,
                    encoding="utf-8",
                )
                self.assertTrue(
                    architecture.find_protected_admission_surface_violations(root)
                )

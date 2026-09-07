use syn::{ImplItemFn, ItemFn, Type, Visibility};

use super::surface_policy::same_signature;
use super::surface_syntax as syntax;

pub fn audit_free(path: &str, item: &ItemFn, violations: &mut Vec<String>) {
    let name = item.sig.ident.to_string();
    let expected = free_ingress(&name);
    let valid = expected.is_some_and(|expected| {
        path.ends_with(expected.path)
            && item.vis == visibility(expected.visibility)
            && same_signature(&item.sig, expected.signature)
            && !syntax::has_cfg_attr(&item.attrs)
    });
    if !valid {
        violations.push(format!(
            "exact-release ingress in {path}: non-allowlisted free function {name}"
        ));
    }
    if syntax::has_cfg_attr(&item.attrs) {
        violations.push(format!("guarded cfg_attr in {path}: free function {name}"));
    }
}

pub fn audit_method(path: &str, owner: &Type, method: &ImplItemFn, violations: &mut Vec<String>) {
    let name = method.sig.ident.to_string();
    let valid = name == "verify_current_pinned"
        && owner_name(owner).as_deref() == Some("PendingSignedInstalledReleaseMetadataV2")
        && path.ends_with("signed_installed_release/frame.rs")
        && method.vis == visibility("pub")
        && same_signature(
            &method.sig,
            concat!(
                "fn verify_current_pinned(self, expected: DigestEqualityMatcherV1) -> ",
                "Result<VerifiedSignedInstalledReleaseV2, ",
                "SignedInstalledReleaseVerificationErrorV2>"
            ),
        )
        && syntax::is_doc_hidden(&method.attrs)
        && !syntax::has_cfg_attr(&method.attrs);
    if !valid {
        violations.push(format!(
            "exact-release ingress in {path}: non-allowlisted method {name}"
        ));
    }
    if syntax::has_cfg_attr(&method.attrs) {
        violations.push(format!("guarded cfg_attr in {path}: method {name}"));
    }
}

struct Expected {
    path: &'static str,
    visibility: &'static str,
    signature: &'static str,
}

fn free_ingress(name: &str) -> Option<Expected> {
    match name {
        "exact" => Some(Expected {
            path: "signed_installed_release/binding/exact.rs",
            visibility: "pub(in super::super)",
            signature: concat!(
                "fn exact(verified: VerifiedSignedUpdateMetadataV2, expected: [u8; 32]) -> ",
                "Result<VerifiedSignedInstalledReleaseV2, ",
                "SignedInstalledReleaseVerificationErrorV2>"
            ),
        }),
        "exact_with_matcher" => Some(Expected {
            path: "signed_installed_release/binding/exact.rs",
            visibility: "pub(in super::super)",
            signature: concat!(
                "fn exact_with_matcher(verified: VerifiedSignedUpdateMetadataV2, ",
                "expected: &DigestEqualityMatcherV1) -> ",
                "Result<VerifiedSignedInstalledReleaseV2, ",
                "SignedInstalledReleaseVerificationErrorV2>"
            ),
        }),
        "verify_exact_signed_installed_release_v2" => Some(Expected {
            path: "signed_installed_release/verification.rs",
            visibility: "pub",
            signature: concat!(
                "fn verify_exact_signed_installed_release_v2(canonical_metadata: &[u8], ",
                "trust: &UpdateTrustRootV2, expected_release_binding: [u8; 32], ",
                "now_unix_seconds: u64) -> Result<VerifiedSignedInstalledReleaseV2, ",
                "SignedInstalledReleaseVerificationErrorV2>"
            ),
        }),
        "verify_current_pinned_with" => Some(Expected {
            path: "signed_installed_release/frame.rs",
            visibility: "",
            signature: concat!(
                "fn verify_current_pinned_with(",
                "pending: PendingSignedInstalledReleaseMetadataV2, ",
                "trust: &UpdateTrustRootV2, now: u64, expected: &DigestEqualityMatcherV1) -> ",
                "Result<VerifiedSignedInstalledReleaseV2, ",
                "SignedInstalledReleaseVerificationErrorV2>"
            ),
        }),
        _ => None,
    }
}

fn visibility(source: &str) -> Visibility {
    if source.is_empty() {
        Visibility::Inherited
    } else {
        syn::parse_str(source).unwrap()
    }
}

fn owner_name(owner: &Type) -> Option<String> {
    let Type::Path(owner) = owner else {
        return None;
    };
    owner
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

use std::collections::BTreeMap;

use syn::{ImplItem, ItemImpl, ItemStruct, Signature};

use super::surface_syntax as syntax;

#[derive(Default)]
pub struct Stats {
    pub exact_structs: usize,
    pub projection_structs: usize,
    pub debug_impls: usize,
    pub exact_methods: BTreeMap<String, usize>,
    pub projection_methods: BTreeMap<String, usize>,
    pub exact_constructions: Vec<String>,
    pub projection_constructor_calls: Vec<String>,
}

pub fn audit_exact_struct(
    path: &str,
    item: &ItemStruct,
    stats: &mut Stats,
    violations: &mut Vec<String>,
) {
    stats.exact_structs += 1;
    if syntax::has_cfg_attr(&item.attrs)
        || !path.ends_with("signed_installed_release/binding.rs")
        || !matches!(item.vis, syn::Visibility::Public(_))
        || syntax::derive_names(&item.attrs) != ["Eq", "PartialEq"]
        || named_private_fields(item)
            != Some(
                [
                    "signed_candidate",
                    "signed_candidate_v3",
                    "candidate_binding_v3",
                ]
                .map(str::to_owned)
                .to_vec(),
            )
    {
        reject(
            violations,
            path,
            "exact-release struct",
            "shape, derives, visibility, or owner changed",
        );
    }
}

pub fn audit_projection_struct(
    path: &str,
    item: &ItemStruct,
    stats: &mut Stats,
    violations: &mut Vec<String>,
) {
    stats.projection_structs += 1;
    let name = item.ident.to_string();
    if syntax::has_cfg_attr(&item.attrs) {
        reject(violations, path, "guarded cfg_attr", &name);
    }
    if item.vis != syn::parse_str::<syn::Visibility>("pub(super)").unwrap() {
        reject(violations, path, "projection visibility", &name);
    }
    if syntax::derive_names(&item.attrs) != ["Eq", "PartialEq"] {
        reject(violations, path, "projection derive", &name);
    }
    if !path.ends_with("binding/candidate_binding.rs")
        || named_private_string_fields(item)
            != Some(
                [
                    "arch",
                    "platform",
                    "product_id",
                    "profile_id",
                    "release_candidate_sha256",
                    "version",
                ]
                .map(str::to_owned)
                .to_vec(),
            )
    {
        reject(violations, path, "projection fields", &name);
    }
}

pub fn audit_exact_impl(
    path: &str,
    item: &ItemImpl,
    stats: &mut Stats,
    violations: &mut Vec<String>,
) {
    if syntax::has_cfg_attr(&item.attrs) {
        reject(violations, path, "guarded cfg_attr", "exact-release impl");
    }
    if item.trait_.is_some() {
        let expected = syn::parse_str::<ItemImpl>(concat!(
            "impl core::fmt::Debug for VerifiedSignedInstalledReleaseV2 {",
            "fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {",
            "formatter.write_str(\"VerifiedSignedInstalledReleaseV2(<opaque>)\")",
            "}}"
        ))
        .unwrap();
        if path.ends_with("signed_installed_release/binding.rs") && item == &expected {
            stats.debug_impls += 1;
        } else {
            reject(
                violations,
                path,
                "exact-release trait impl",
                "only the opaque Debug impl is allowed",
            );
        }
        return;
    }
    for member in &item.items {
        let ImplItem::Fn(method) = member else {
            reject(
                violations,
                path,
                "exact-release impl item",
                "only allowlisted methods are allowed",
            );
            continue;
        };
        let name = method.sig.ident.to_string();
        let Some((signature, owner)) = exact_methods().get(name.as_str()).copied() else {
            reject(violations, path, "exact-release method", &name);
            continue;
        };
        if method.vis != syn::parse_str::<syn::Visibility>("pub").unwrap()
            || !same_signature(&method.sig, signature)
            || !syntax::is_doc_hidden(&method.attrs)
            || syntax::has_cfg_attr(&method.attrs)
            || !path.ends_with(owner)
        {
            reject(
                violations,
                path,
                "exact-release method",
                &format!("non-exact {name}"),
            );
        } else {
            *stats.exact_methods.entry(name).or_default() += 1;
        }
    }
}

pub fn audit_projection_impl(
    path: &str,
    item: &ItemImpl,
    stats: &mut Stats,
    violations: &mut Vec<String>,
) {
    if syntax::has_cfg_attr(&item.attrs) {
        reject(violations, path, "guarded cfg_attr", "projection impl");
    }
    if item.trait_.is_some() {
        reject(
            violations,
            path,
            "projection trait impl",
            "traits are forbidden",
        );
        return;
    }
    for member in &item.items {
        let ImplItem::Fn(method) = member else {
            reject(
                violations,
                path,
                "projection impl item",
                "only allowlisted methods are allowed",
            );
            continue;
        };
        let name = method.sig.ident.to_string();
        let expected = match name.as_str() {
            "from_target" => "fn from_target(target: &UpdateTargetV2) -> Self",
            "matches" => "fn matches(&self, candidate: &CandidateBindingV3) -> bool",
            _ => {
                reject(violations, path, "projection method", &name);
                continue;
            }
        };
        let visibility = if name == "from_target" {
            syn::parse_str::<syn::Visibility>("pub(super)").unwrap()
        } else {
            syn::Visibility::Inherited
        };
        if method.vis != visibility
            || !same_signature(&method.sig, expected)
            || syntax::has_cfg_attr(&method.attrs)
            || !path.ends_with("binding/candidate_binding.rs")
        {
            reject(
                violations,
                path,
                "projection constructor ownership",
                &format!("non-exact {name}"),
            );
        } else {
            *stats.projection_methods.entry(name).or_default() += 1;
        }
    }
}

pub fn exact_methods() -> BTreeMap<&'static str, (&'static str, &'static str)> {
    [
        ("native_enrollment_tuple_v3", ("const fn native_enrollment_tuple_v3(&self) -> Option<&VerifiedSignedNativeEnrollmentTupleV3>", "signed_installed_release/binding.rs")),
        ("matches_desktop_digest", ("fn matches_desktop_digest(&self, candidate: &[u8; 32]) -> bool", "binding/matchers.rs")),
        ("matches_writer_digest", ("fn matches_writer_digest(&self, candidate: &[u8; 32]) -> bool", "binding/matchers.rs")),
        ("matches_daemon_digest", ("fn matches_daemon_digest(&self, candidate: &[u8; 32]) -> bool", "binding/matchers.rs")),
        ("matches_contract_digest", ("fn matches_contract_digest(&self, candidate: &[u8; 32]) -> bool", "binding/matchers.rs")),
        ("matches_release_binding", ("fn matches_release_binding(&self, candidate: &[u8; 32]) -> bool", "binding/matchers.rs")),
        ("matches_desktop_code_identity", ("fn matches_desktop_code_identity(&self, identifier: &str, team_identifier: &str, cdhash: &str) -> bool", "binding/matchers.rs")),
        ("matches_writer_code_identity", ("fn matches_writer_code_identity(&self, identifier: &str, team_identifier: &str, cdhash: &str) -> bool", "binding/matchers.rs")),
        ("matches_daemon_code_identity", ("fn matches_daemon_code_identity(&self, identifier: &str, team_identifier: &str, cdhash: &str) -> bool", "binding/matchers.rs")),
        ("release_binding_matcher", ("fn release_binding_matcher(&self) -> DigestEqualityMatcherV1", "binding/matchers.rs")),
        ("matches_native_enrollment_v3_candidate_binding", ("fn matches_native_enrollment_v3_candidate_binding(&self, canonical_binding: &[u8]) -> bool", "binding/candidate_binding.rs")),
    ]
    .into_iter()
    .collect()
}

pub fn validate_counts(stats: &Stats, violations: &mut Vec<String>) {
    if stats.exact_structs != 1 || stats.projection_structs != 1 || stats.debug_impls != 1 {
        violations.push("guarded struct/Debug ownership count changed".into());
    }
    for name in exact_methods().keys() {
        if stats.exact_methods.get(*name) != Some(&1) {
            violations.push(format!("exact-release method count changed: {name}"));
        }
    }
    for name in ["from_target", "matches"] {
        if stats.projection_methods.get(name) != Some(&1) {
            violations.push(format!("projection method count changed: {name}"));
        }
    }
    if stats.exact_constructions.len() != 1
        || !stats.exact_constructions[0].ends_with("binding/exact.rs")
    {
        violations.push("exact-release construction ownership changed".into());
    }
    if stats.projection_constructor_calls.len() != 1
        || !stats.projection_constructor_calls[0].ends_with("binding/exact.rs")
    {
        violations.push("projection constructor ownership changed".into());
    }
}

fn named_private_fields(item: &ItemStruct) -> Option<Vec<String>> {
    item.fields
        .iter()
        .map(|field| {
            matches!(field.vis, syn::Visibility::Inherited)
                .then(|| field.ident.as_ref().map(ToString::to_string))
                .flatten()
        })
        .collect()
}

fn named_private_string_fields(item: &ItemStruct) -> Option<Vec<String>> {
    let fields = named_private_fields(item)?;
    let all_strings = item.fields.iter().all(|field| {
        matches!(&field.ty, syn::Type::Path(value)
            if value.qself.is_none()
                && value.path.segments.len() == 1
                && value.path.is_ident("String"))
    });
    all_strings.then_some(fields)
}

pub fn same_signature(actual: &Signature, expected: &str) -> bool {
    let mut actual = actual.clone();
    let mut expected = syn::parse_str::<Signature>(expected).unwrap();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

fn reject(violations: &mut Vec<String>, path: &str, category: &str, detail: &str) {
    violations.push(format!("{category} in {path}: {detail}"));
}

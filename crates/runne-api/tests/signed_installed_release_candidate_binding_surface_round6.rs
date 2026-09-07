use std::path::Path;

#[path = "support/signed_release_surface_audit.rs"]
mod surface_audit;
#[path = "support/signed_release_surface_ingress.rs"]
mod surface_ingress;
#[path = "support/signed_release_surface_policy.rs"]
mod surface_policy;
#[path = "support/signed_release_surface_sources.rs"]
mod surface_sources;
#[path = "support/signed_release_surface_syntax.rs"]
mod surface_syntax;

fn audit_extra(source: &str) -> Vec<String> {
    let mut sources =
        surface_sources::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap();
    sources.push(("binding/round6.rs".into(), source.into()));
    surface_audit::audit(&sources)
}

fn assert_rejected(source: &str, category: &str) {
    let violations = audit_extra(source);
    assert!(
        violations.iter().any(|value| value.contains(category)),
        "{category} escaped: {source}\n{violations:?}"
    );
}

#[test]
fn parent_impl_associated_equality_is_rejected() {
    for (family, visibility) in [
        ("crate::VerifiedSignedInstalledReleaseV2", "pub(super)"),
        ("crate::VerifiedCandidateBindingV3", "pub"),
    ] {
        assert_rejected(
            &format!(
                "trait Slot {{ type Value; }}
                 struct Helper<T>(core::marker::PhantomData<T>);
                 impl<T> Helper<T>
                 where T: Slot<Value = {family}>
                 {{ {visibility} fn leak(source: &T::Value) -> Option<String>
                    {{ unimplemented!() }} }}"
            ),
            "guarded associated equality",
        );
    }
}

#[test]
fn parent_trait_associated_equality_is_rejected() {
    for family in [
        "crate::VerifiedSignedInstalledReleaseV2",
        "crate::VerifiedCandidateBindingV3",
    ] {
        assert_rejected(
            &format!(
                "trait Slot {{ type Value; }}
                 trait Parent: Slot<Value = {family}> {{
                     fn leak(&self, source: &Self::Value) -> Option<String>;
                 }}"
            ),
            "guarded associated equality",
        );
    }
}

#[test]
fn associated_equality_alias_and_production_cfg_are_discovered() {
    let family = "crate::VerifiedSignedInstalledReleaseV2";
    for prefix in ["", "#[cfg(not(test))] "] {
        assert_rejected(
            &format!(
                "trait Slot {{ type Value; }}
                 {prefix}type Alias = {family};
                 struct Helper<T>(core::marker::PhantomData<T>);
                 impl<T> Helper<T> where T: Slot<Value = Alias> {{
                     pub(super) fn leak(source: &T::Value) -> Option<String>
                         {{ unimplemented!() }}
                 }}"
            ),
            "guarded associated equality",
        );
    }
}

#[test]
fn test_only_associated_equality_is_not_a_production_violation() {
    let source = "trait Slot { type Value; }
                   struct Helper<T>(core::marker::PhantomData<T>);
                   #[cfg(test)]
                   impl<T> Helper<T>
                   where T: Slot<Value = crate::VerifiedSignedInstalledReleaseV2> {}
                   ";
    assert!(
        audit_extra(source).is_empty(),
        "test-only equality was audited"
    );
}

#[test]
fn associated_equality_is_rejected_in_trait_impl_and_function_bounds() {
    let family = "crate::VerifiedSignedInstalledReleaseV2";
    for source in [
        format!(
            "trait Slot {{ type Value; }}
             struct Helper<T>(core::marker::PhantomData<T>);
             impl<T> Slot<Value = {family}> for Helper<T> {{ }}"
        ),
        format!(
            "trait Slot {{ type Value; }}
             fn leak<T: Slot<Value = {family}>>(source: &T::Value)
                 -> Option<String> {{ unimplemented!() }}"
        ),
    ] {
        assert_rejected(&source, "guarded associated equality");
    }
}

#[test]
fn unrelated_associated_equality_does_not_taint_shorthand_projection() {
    let source = "trait Slot { type Value; }
                   struct Helper<T>(core::marker::PhantomData<T>);
                   impl<T> Helper<T> where T: Slot<Value = String> {
                       pub(super) fn leak(source: &T::Value) -> Option<String>
                           { unimplemented!() }
                   }";
    assert!(
        audit_extra(source).is_empty(),
        "benign equality was rejected"
    );
}

#[test]
fn independent_associated_equalities_do_not_share_a_family_name() {
    let source = "trait GuardedSlot { type Value; }
                   struct Guarded<T>(core::marker::PhantomData<T>);
                   impl<T> Guarded<T>
                   where T: GuardedSlot<Value = crate::VerifiedSignedInstalledReleaseV2> {}
                   trait PlainSlot { type Value; }
                   struct Plain<T>(core::marker::PhantomData<T>);
                   impl<T> Plain<T> where T: PlainSlot<Value = String> {
                       pub(super) fn leak(source: &T::Value) -> Option<String>
                           { unimplemented!() }
                   }";
    let violations = audit_extra(source);
    assert!(
        violations
            .iter()
            .any(|value| value.contains("guarded associated equality")),
        "guarded equality was not rejected: {violations:?}"
    );
    assert!(
        !violations
            .iter()
            .any(|value| value.contains("binding/round6.rs: non-allowlisted method leak")),
        "benign equality inherited guarded taint: {violations:?}"
    );
}

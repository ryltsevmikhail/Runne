use runne_plugin_host::{
    PluginAuthorityPort, PluginAuthorityRegistry, PluginClass, PluginHookDefinition,
    PluginHookFailurePolicy, PluginHookId, PluginHookInvocation, PluginHookInvocationId,
    PluginPackageCapture, PluginPackageContent, PluginToolDescriptor, ordered_plugin_hooks,
    publish_plugin_tools,
};
use runne_plugin_protocol::id::PluginId;
use runne_tools::{ToolId, ToolRegistry, ToolVersion};
use serde_json::json;

const BUILTIN_MANIFEST: &[u8] = b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\nfile_table_digest=sha256:323c9209e107923ed099aa3e8a015ea71cc0c45ea1f3eae041c609bfbd1f5674\nprotocol_profile=builtin-profile-v2|sha256:66e64e0e083bc81b3b8043f9c3aeb306065abb7e0c47456c9f28cdb27e77823a\nfile=entrypoint|executable|39|sha256:c62efb3b0643adea80e7a6eb62c47661b285be4d8c2145b7eb5cfc7d82ba8ceb\nfile=package|data|36|sha256:035f422735e30a22bed0262055206c36fca329f1e2fe2dbad8191a9441fb3572\n";
const BUILTIN_PROFILE: &[u8] = b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n";

fn verified_package() -> runne_plugin_host::VerifiedPluginPackage {
    let source = PluginPackageCapture::capture(
        PluginPackageContent::try_new(
            b"runne-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            b"runne-plugin-host/builtin-entrypoint-v1".to_vec(),
            BUILTIN_PROFILE.to_vec(),
            b"runne-plugin-host/builtin-trust-binding-v1".to_vec(),
        )
        .unwrap(),
        PluginClass::Extension,
    );
    PluginAuthorityRegistry::built_in()
        .verifier_for(&source)
        .unwrap()
        .verify(source)
        .unwrap()
}

#[test]
fn legacy_package_only_tool_publication_is_fail_closed() {
    let tool_id = ToolId::new("builtin::search").unwrap();
    let version = ToolVersion::new("1.0.0").unwrap();
    let mut registry = ToolRegistry::new();

    let result = publish_plugin_tools(
        &verified_package(),
        vec![PluginToolDescriptor::new(
            PluginId::new("builtin").unwrap(),
            tool_id,
            version,
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": false
            }),
        )],
        &mut registry,
    );
    assert!(result.is_err());
    assert!(
        registry
            .snapshot(&[ToolId::new("builtin::search").unwrap()])
            .is_err()
    );
}

#[test]
fn duplicate_plugin_tool_batch_is_atomic() {
    let tool_id = ToolId::new("builtin::duplicate").unwrap();
    let version = ToolVersion::new("1.0.0").unwrap();
    let schema = json!({"type": "object"});
    let mut registry = ToolRegistry::new();

    assert!(
        publish_plugin_tools(
            &verified_package(),
            vec![
                PluginToolDescriptor::new(
                    PluginId::new("builtin").unwrap(),
                    tool_id.clone(),
                    version,
                    schema.clone(),
                ),
                PluginToolDescriptor::new(
                    PluginId::new("builtin").unwrap(),
                    tool_id.clone(),
                    version,
                    schema,
                ),
            ],
            &mut registry,
        )
        .is_err()
    );
    assert!(registry.snapshot(&[tool_id]).is_err());
}

#[test]
fn verified_but_not_active_package_cannot_publish_routable_tools() {
    let package = verified_package();
    let mut registry = ToolRegistry::new();
    let result = publish_plugin_tools(
        &package,
        vec![PluginToolDescriptor::new(
            PluginId::new("builtin").unwrap(),
            ToolId::new("builtin::must-not-route").unwrap(),
            ToolVersion::new("1.0.0").unwrap(),
            json!({"type": "object"}),
        )],
        &mut registry,
    );

    assert!(result.is_err());
    assert!(
        registry
            .snapshot(&[ToolId::new("builtin::must-not-route").unwrap()])
            .is_err()
    );
}

#[test]
fn hook_descriptors_and_payloads_are_bounded_immutable_values() {
    let definition = PluginHookDefinition::new(
        10,
        PluginId::new("plugin-a").unwrap(),
        PluginHookId::new("before-run").unwrap(),
        PluginHookFailurePolicy::Required,
    );
    assert_eq!(definition.priority(), 10);
    assert_eq!(definition.plugin_id().as_str(), "plugin-a");
    assert_eq!(definition.hook_id().as_str(), "before-run");

    let invocation = PluginHookInvocation::try_new(
        PluginHookInvocationId::new("invocation").unwrap(),
        10,
        b"payload".to_vec(),
    )
    .unwrap();
    assert!(
        PluginHookInvocation::try_new_with_digest(
            PluginHookInvocationId::new("invocation").unwrap(),
            10,
            b"changed".to_vec(),
            *invocation.payload_digest()
        )
        .is_err()
    );
}

#[test]
fn global_hook_order_includes_plugin_owner() {
    let ordered = ordered_plugin_hooks(&[
        PluginHookDefinition::new(
            1,
            PluginId::new("plugin-b").unwrap(),
            PluginHookId::new("a").unwrap(),
            PluginHookFailurePolicy::Optional,
        ),
        PluginHookDefinition::new(
            1,
            PluginId::new("plugin-a").unwrap(),
            PluginHookId::new("z").unwrap(),
            PluginHookFailurePolicy::Optional,
        ),
        PluginHookDefinition::new(
            0,
            PluginId::new("plugin-z").unwrap(),
            PluginHookId::new("z").unwrap(),
            PluginHookFailurePolicy::Optional,
        ),
    ])
    .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|definition| definition.plugin_id().as_str())
            .collect::<Vec<_>>(),
        ["plugin-z", "plugin-a", "plugin-b"]
    );
}

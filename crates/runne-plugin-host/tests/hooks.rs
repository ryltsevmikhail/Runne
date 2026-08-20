use runne_plugin_host::{
    PluginAuthorityPort, PluginAuthorityRegistry, PluginClass, PluginHookDefinition,
    PluginHookFailurePolicy, PluginHookId, PluginHookInvocation, PluginHookInvocationId,
    PluginPackageCapture, PluginPackageContent, PluginToolDescriptor, ordered_plugin_hooks,
    publish_plugin_tools,
};
use runne_plugin_protocol::id::PluginId;
use runne_tools::{ToolId, ToolRegistry, ToolVersion};
use serde_json::json;

const BUILTIN_MANIFEST: &[u8] = b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\nfile_table_digest=sha256:7c095321ed00395bc7d98a7256f7493884c68727c9390ca67d6fa0fd5e7d0ef8\nprotocol_profile=builtin-profile-v2|sha256:6dbddbd754f8bff3d62cfefd31095bce32563ac2627705c924261c0bfe4f6c5d\nfile=entrypoint|executable|40|sha256:b819bdc75d5ae1d0f9f0611f08f58802c88cbbd015bef7aff3a0c3160e832834\nfile=package|data|37|sha256:c48131eae8e78a0f2fccc5d0bae39d73e44a8a1eb74484b1cc500e43de7e8253\n";
const BUILTIN_PROFILE: &[u8] = b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n";

fn verified_package() -> runne_plugin_host::VerifiedPluginPackage {
    let source = PluginPackageCapture::capture(
        PluginPackageContent::try_new(
            b"gocode-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            b"gocode-plugin-host/builtin-entrypoint-v1".to_vec(),
            BUILTIN_PROFILE.to_vec(),
            b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
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

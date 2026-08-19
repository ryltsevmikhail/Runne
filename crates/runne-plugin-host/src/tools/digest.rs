fn tool_descriptor_digest(descriptors: &[PluginToolDescriptor]) -> [u8; 32] {
    let mut descriptors = descriptors
        .iter()
        .map(|descriptor| {
            (
                descriptor.plugin_id.as_str(),
                descriptor.tool_id.as_str(),
                descriptor.version,
                &descriptor.input_schema,
            )
        })
        .collect::<Vec<_>>();
    descriptors.sort_by(|left, right| (left.0, left.1, left.2).cmp(&(right.0, right.1, right.2)));
    let mut hasher = Sha256::new();
    hasher.update(b"RUNNE_PLUGIN_TOOL_DESCRIPTOR_SNAPSHOT_V1\0");
    hasher.update((descriptors.len() as u64).to_be_bytes());
    for (plugin_id, tool_id, tool_version, schema) in descriptors {
        hasher.update((plugin_id.len() as u64).to_be_bytes());
        hasher.update(plugin_id.as_bytes());
        hasher.update((tool_id.len() as u64).to_be_bytes());
        hasher.update(tool_id.as_bytes());
        let version = tool_version.to_string();
        hasher.update((version.len() as u64).to_be_bytes());
        hasher.update(version.as_bytes());
        let schema = serde_json::to_vec(schema).expect("serde_json::Value always serializes");
        hasher.update((schema.len() as u64).to_be_bytes());
        hasher.update(schema);
    }
    hasher.finalize().into()
}

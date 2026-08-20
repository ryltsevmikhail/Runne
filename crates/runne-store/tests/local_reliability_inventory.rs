use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    entries: Vec<Entry>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    category: String,
    package: String,
    target: String,
    fully_qualified_test_name: String,
}

#[test]
fn named_recovery_and_telemetry_inventory_is_complete() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = workspace.join("scripts/rc0_candidate/inventories/local-reliability-v1.json");
    let inventory: Inventory = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(inventory.schema, "gocode.local-reliability-inventory/1");

    let mut expected = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in inventory.entries {
        assert!(matches!(entry.category.as_str(), "recovery" | "telemetry"));
        assert_eq!(entry.package, "runne-store");
        assert!(
            expected
                .entry(entry.target)
                .or_default()
                .insert(entry.fully_qualified_test_name),
            "duplicate reliability inventory entry"
        );
    }

    let targets = [
        "operational_telemetry",
        "provider_dispatch_recovery",
        "provider_recovery_full_audit",
        "recovery_fixture_compatibility",
    ];
    assert_eq!(
        expected.keys().map(String::as_str).collect::<Vec<_>>(),
        targets
    );
    for target in targets {
        let listed = list_tests(&workspace, target);
        let governed = if target == "recovery_fixture_compatibility" {
            listed
                .into_iter()
                .filter(|name| !name.starts_with("recovery_fixtures::tests::"))
                .collect()
        } else {
            listed
        };
        assert_eq!(expected.get(target).unwrap(), &governed, "{target}");
    }
}

fn list_tests(workspace: &Path, target: &str) -> BTreeSet<String> {
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "--locked",
            "-p",
            "runne-store",
            "--test",
            target,
            "--",
            "--list",
        ])
        .current_dir(workspace)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect()
}

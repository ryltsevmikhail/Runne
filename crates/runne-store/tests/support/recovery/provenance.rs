use std::path::Path;

use super::recovery_fixtures::RecoveryFixtureManifest;
use syn::{ImplItem, Item, ItemImpl, Type};

pub(crate) fn validate_manifest_provenance(
    workspace: &Path,
    manifest: &RecoveryFixtureManifest,
) -> Result<(), String> {
    for entry in &manifest.fixtures {
        let spec = format!("{}@{}", entry.source_commit, entry.writer_snapshot);
        let snapshot_root = workspace.join("crates/runne-store/tests/fixtures/recovery");
        let snapshot = std::fs::read(snapshot_root.join(&entry.writer_snapshot))
            .map_err(|error| format!("cannot read writer snapshot {spec}: {error}"))?;
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&snapshot);
            hasher.finalize()
        };
        if format!("{digest:x}") != entry.writer_snapshot_sha256 {
            return Err(format!("writer snapshot digest mismatch for {spec}"));
        }
        let source = String::from_utf8(snapshot)
            .map_err(|error| format!("{spec} is not UTF-8 source: {error}"))?;
        validate_writer_symbol(&spec, &source, &entry.writer_symbol)?;
    }
    Ok(())
}

fn validate_writer_symbol(spec: &str, source: &str, symbol: &str) -> Result<(), String> {
    let (receiver, method) = symbol
        .split_once("::")
        .filter(|(receiver, method)| !receiver.is_empty() && !method.is_empty())
        .ok_or_else(|| format!("invalid writer symbol {symbol:?} for {spec}"))?;
    let file = syn::parse_file(source)
        .map_err(|error| format!("cannot parse writer source {spec}: {error}"))?;
    if !file.items.iter().any(|item| {
        let Item::Impl(implementation) = item else {
            return false;
        };
        implementation_matches_receiver(implementation, receiver)
            && implementation
                .items
                .iter()
                .any(|item| matches!(item, ImplItem::Fn(function) if function.sig.ident == method))
    }) {
        return Err(format!("writer symbol {symbol} does not resolve in {spec}"));
    }
    Ok(())
}

fn implementation_matches_receiver(implementation: &ItemImpl, receiver: &str) -> bool {
    type_terminal_identifier(&implementation.self_ty).as_deref() == Some(receiver)
        || implementation
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .is_some_and(|segment| segment.ident == receiver)
}

fn type_terminal_identifier(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn manifest() -> RecoveryFixtureManifest {
        crate::recovery_fixtures::load_manifest().unwrap()
    }

    #[test]
    fn unit_of_work_commit_conversation_is_not_a_writer_symbol() {
        let mut manifest = manifest();
        manifest.fixtures[0].writer_symbol = "UnitOfWork::commit_conversation".into();

        assert!(validate_manifest_provenance(&workspace(), &manifest).is_err());
    }

    #[test]
    fn conversation_repository_commit_is_not_a_writer_symbol() {
        let mut manifest = manifest();
        manifest.fixtures[1].writer_symbol = "ConversationRepository::commit".into();

        assert!(validate_manifest_provenance(&workspace(), &manifest).is_err());
    }

    #[test]
    fn writer_symbol_rejects_method_prefix_and_comment_decoys() {
        assert!(
            validate_writer_symbol(
                "test",
                "// impl UnitOfWork\n// fn commit",
                "UnitOfWork::commit"
            )
            .is_err()
        );
        assert!(
            validate_writer_symbol(
                "test",
                "impl UnitOfWork { fn commit_extra() {} }",
                "UnitOfWork::commit"
            )
            .is_err()
        );
    }

    #[test]
    fn writer_symbol_rejects_a_missing_method() {
        assert!(
            validate_writer_symbol("test", "impl UnitOfWork {}", "UnitOfWork::commit").is_err()
        );
    }

    #[test]
    fn provenance_rejects_each_tampered_writer_snapshot() {
        for index in 0..manifest().fixtures.len() {
            let mut manifest = manifest();
            manifest.fixtures[index].writer_snapshot_sha256 = "0".repeat(64);

            assert!(validate_manifest_provenance(&workspace(), &manifest).is_err());
        }
    }

    #[test]
    fn provenance_rejects_a_missing_writer_snapshot() {
        let mut manifest = manifest();
        manifest.fixtures[0].writer_snapshot = "provenance/absent.rs".into();

        assert!(validate_manifest_provenance(&workspace(), &manifest).is_err());
    }
}

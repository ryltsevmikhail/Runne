use super::semantic_index::{PathOrigin, Resolution, SemanticIndex};
use super::source_model::ScopeId;
use super::symbols::{ModuleRecord, TypeKind};

pub(super) fn path_origin(index: &SemanticIndex, scope: ScopeId, path: &syn::Path) -> PathOrigin {
    if let Resolution::Exact(id) = index.resolve_type(scope, path) {
        return if index
            .type_record(id)
            .is_some_and(|record| matches!(record.kind, TypeKind::CanonicalTarget))
        {
            PathOrigin::CanonicalTarget
        } else {
            PathOrigin::Local
        };
    }
    let parts = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let Some(first) = parts.first() else {
        return PathOrigin::Unknown;
    };
    let Some(module) = index.modules.iter().find(|module| module.scope == scope) else {
        return PathOrigin::Unknown;
    };
    if local_root(index, module, first) {
        return PathOrigin::Local;
    }
    if parts.len() == 1
        && let Some(import) = index
            .imports
            .iter()
            .find(|import| import.scope == scope && import.alias.as_deref() == Some(first.as_str()))
    {
        let Some(root) = import.path.first() else {
            return PathOrigin::Unknown;
        };
        if root == &index.target.crate_name {
            return PathOrigin::CanonicalTarget;
        }
        return if local_root(index, module, root) {
            PathOrigin::Local
        } else {
            PathOrigin::ExternalOpaque
        };
    }
    if parts.len() > 1 || path.leading_colon.is_some() {
        PathOrigin::ExternalOpaque
    } else {
        PathOrigin::Unknown
    }
}

fn local_root(index: &SemanticIndex, module: &ModuleRecord, root: &str) -> bool {
    let mut path = module.path.clone();
    loop {
        let mut candidate = path.clone();
        candidate.push(root.to_owned());
        if index.modules.iter().any(|item| {
            item.package == module.package && item.target == module.target && item.path == candidate
        }) {
            return true;
        }
        if path.pop().is_none() {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_root_compares_against_target_descriptor_crate_name() {
        let source =
            "use other_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;";
        let mut index = SemanticIndex::from_source(source).expect("fixture index must build");
        let scope = index
            .modules
            .iter()
            .find(|module| module.path.is_empty())
            .expect("fixture root module")
            .scope;
        let path = syn::parse_str::<syn::Path>("Pending").expect("fixture path must parse");

        assert_eq!(
            path_origin(&index, scope, &path),
            PathOrigin::ExternalOpaque,
            "without a descriptor match the import root stays opaque"
        );

        index.target.crate_name = "other_identity".into();
        assert_eq!(
            path_origin(&index, scope, &path),
            PathOrigin::CanonicalTarget,
            "import root comparison must follow the target descriptor"
        );
    }
}

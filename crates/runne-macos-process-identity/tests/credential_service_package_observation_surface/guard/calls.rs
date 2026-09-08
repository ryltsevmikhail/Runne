use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use super::analyzer::{GuardVerdict, analyze, analyze_source};
use super::semantic_index::SemanticIndex;

/// Fixture convenience only; unresolved provenance must never become a count.
#[track_caller]
pub fn count_credential_service_calls(source: &str) -> usize {
    match analyze_source(source) {
        GuardVerdict::Clean => 0,
        GuardVerdict::Calls(sites) => sites.len(),
        verdict @ GuardVerdict::Inconclusive(_) => {
            panic!("source analysis is inconclusive: {verdict:?}")
        }
    }
}

pub fn assert_workspace_has_no_credential_service_calls(workspace: &Path, facade: &Path) {
    let snapshot = super::collect_workspace_credential_service_consumer_snapshot(workspace, facade);
    let index = SemanticIndex::build(&snapshot).unwrap_or_else(|error| {
        let path = error
            .source
            .and_then(|source| snapshot.graph.node(source))
            .map(|node| &node.canonical_path);
        panic!("incomplete production source graph at {path:?}: {error:?}")
    });
    let verdict = analyze(&index);
    match verdict {
        GuardVerdict::Clean => {}
        GuardVerdict::Calls(sites) => {
            let details = sites
                .iter()
                .take(20)
                .map(|site| {
                    let path = snapshot
                        .graph
                        .node(site.source)
                        .map(|node| &node.canonical_path);
                    format!("{path:?}: {:?}: {:?}", site.syntax, site.method)
                })
                .collect::<Vec<_>>();
            panic!("{} production calls (first 20): {details:#?}", sites.len());
        }
        GuardVerdict::Inconclusive(sites) => {
            let mut reasons = BTreeMap::new();
            let mut seen = HashSet::new();
            for site in &sites {
                *reasons
                    .entry(format!("{:?}", site.reason))
                    .or_insert(0_usize) += 1;
            }
            let details = sites
                .iter()
                .filter(|site| seen.insert((site.source, format!("{:?}", site.reason))))
                .take(20)
                .map(|site| {
                    let path = site
                        .source
                        .and_then(|id| snapshot.graph.node(id))
                        .map(|node| &node.canonical_path);
                    format!(
                        "{path:?}: {:?}: {:?}: {}",
                        site.syntax, site.reason, site.detail
                    )
                })
                .collect::<Vec<_>>();
            panic!(
                "{} unresolved production sites; reasons: {reasons:?}; \
                 first 20 source/reason groups: {details:#?}",
                sites.len()
            );
        }
    }
}

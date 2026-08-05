#[path = "process_contract/source_lexer.rs"]
mod source_lexer;
#[path = "process_contract/source_lexer_concat.rs"]
mod source_lexer_concat;
#[path = "process_contract/source_manifest.rs"]
mod source_manifest;
#[path = "process_contract/source_scan_alias.rs"]
mod source_scan_alias;

include!("process_contract/source_scan.rs");
include!("process_contract/integration_surface_scan.rs");
include!("process_contract/output.rs");
include!("process_contract/control.rs");
include!("process_contract/public_api.rs");
include!("process_contract/scenario_matrix.rs");

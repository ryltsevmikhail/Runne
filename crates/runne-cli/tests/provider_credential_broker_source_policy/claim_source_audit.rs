use syn::visit::{self, Visit};
use syn::{ExprCall, ExprMethodCall, FnArg, Item, ItemFn, Type};

const CLAIM_SOURCE: &str = include_str!("../../src/cli/provider_credential_broker/claim.rs");
const FLOW_SOURCE: &str = include_str!("../../src/cli/provider_credential_broker/claim/flow.rs");
const DEADLINE_SOURCE: &str =
    include_str!("../../src/cli/provider_credential_broker/qualified_deadline.rs");

#[test]
fn production_claim_consumes_only_the_authenticated_native_bundle() {
    let violations = claim_source_violations(CLAIM_SOURCE, FLOW_SOURCE);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn claim_policy_rejects_endpoint_injection_and_ticket_reread() {
    let cases = [
        (
            CLAIM_SOURCE.replace(
            "writers: NativeProviderCredentialWriters",
            "endpoint: AuthenticatedDaemonControlEndpoint, writers: NativeProviderCredentialWriters",
        ),
            FLOW_SOURCE.to_owned(),
        ),
        (
            CLAIM_SOURCE.replace("flow::claim_socket(", "flow::claim_bypass("),
            FLOW_SOURCE.to_owned(),
        ),
        (
            CLAIM_SOURCE.to_owned(),
            FLOW_SOURCE.replace(".claim_on(", ".read_frame("),
        ),
    ];
    assert!(
        cases
            .iter()
            .all(|(claim, flow)| !claim_source_violations(claim, flow).is_empty())
    );
}

#[test]
fn qualified_socket_deadline_surrounds_only_claim_exchange() {
    let start = FLOW_SOURCE
        .find("QualifiedSocketControl::new(control)")
        .unwrap();
    let claim = FLOW_SOURCE[start..]
        .find("claim_ticket(&mut qualified")
        .unwrap()
        + start;
    let finish = FLOW_SOURCE[claim..].find(".finish()").unwrap() + claim;
    let handoff = FLOW_SOURCE[finish..].find("finish_claim(").unwrap() + finish;
    assert!(start < claim && claim < finish && finish < handoff);
    assert!(DEADLINE_SOURCE.contains("set_read_timeout(Some(remaining(self.deadline)?))"));
    assert!(DEADLINE_SOURCE.contains("set_write_timeout(Some(remaining(self.deadline)?))"));
    assert!(!CLAIM_SOURCE.contains("configure_socket"));
}

fn claim_source_violations(claim_source: &str, flow_source: &str) -> Vec<String> {
    let file = match syn::parse_file(claim_source) {
        Ok(file) => file,
        Err(error) => return vec![format!("claim source does not parse: {error}")],
    };
    let flow = match syn::parse_file(flow_source) {
        Ok(file) => file,
        Err(error) => return vec![format!("claim flow does not parse: {error}")],
    };
    let Some(function) = one_function(&file.items, "claim_writer_authorization") else {
        return vec!["expected one production claim".into()];
    };
    let Some(socket) = one_function(&flow.items, "claim_socket") else {
        return vec!["expected one socket claim core".into()];
    };
    let Some(ticket) = one_function(&flow.items, "claim_ticket") else {
        return vec!["expected one ticket claim gate".into()];
    };
    let mut violations = Vec::new();
    if function.sig.inputs.len() != 2
        || !is_named_type(
            &function.sig.inputs[0],
            "writers",
            "NativeProviderCredentialWriters",
        )
        || !is_named_type(
            &function.sig.inputs[1],
            "secret_input",
            "CredentialSecretInputPresence",
        )
    {
        violations.push(
            "production claim must accept only authenticated writers and detected secret presence"
                .into(),
        );
    }
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    if calls.into_authenticated_parts != 1 {
        violations.push("claim must consume exactly one authenticated parts bundle".into());
    }
    if calls.claim_socket != 1 || calls.claim_on != 0 || calls.read_frame != 0 {
        violations.push("outer claim must delegate exactly once to the socket core".into());
    }

    if socket.sig.inputs.len() != 6
        || !is_named_type(&socket.sig.inputs[1], "channel", "BrokerChannelBinding")
        || !is_named_type(
            &socket.sig.inputs[2],
            "ticket",
            "PendingCredentialIssueTicketV1",
        )
        || !is_named_type(
            &socket.sig.inputs[5],
            "secret_input",
            "CredentialSecretInputPresence",
        )
    {
        violations
            .push("shared core must retain typed channel, ticket, and secret presence".into());
    }
    let mut ticket_calls = Calls::default();
    ticket_calls.visit_block(&ticket.block);
    if ticket_calls.claim_on != 1
        || ticket_calls.into_authenticated_parts != 0
        || ticket_calls.read_frame != 0
    {
        violations.push("ticket gate must consume one real pending ticket without reread".into());
    }
    violations
}

fn one_function<'a>(items: &'a [Item], name: &str) -> Option<&'a ItemFn> {
    let mut matches = items.iter().filter_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = matches.next()?;
    matches.next().is_none().then_some(function)
}

fn is_named_type(argument: &FnArg, name: &str, expected_type: &str) -> bool {
    let FnArg::Typed(argument) = argument else {
        return false;
    };
    let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
        return false;
    };
    let Type::Path(path) = argument.ty.as_ref() else {
        return false;
    };
    binding.ident == name
        && binding.by_ref.is_none()
        && binding.mutability.is_none()
        && binding.subpat.is_none()
        && path.qself.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == expected_type
}

#[derive(Default)]
struct Calls {
    into_authenticated_parts: usize,
    claim_on: usize,
    read_frame: usize,
    claim_socket: usize,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        match call.method.to_string().as_str() {
            "into_authenticated_parts" => self.into_authenticated_parts += 1,
            "claim_on" => self.claim_on += 1,
            "read_frame" => self.read_frame += 1,
            _ => {}
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "claim_socket")
        {
            self.claim_socket += 1;
        }
        visit::visit_expr_call(self, call);
    }
}

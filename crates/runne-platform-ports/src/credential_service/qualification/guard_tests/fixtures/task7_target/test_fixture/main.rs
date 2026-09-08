mod aliases;

use aliases::{
    ArrayWrapped, BareFnWrapped, Borrowed, Boxed, GenericWrapped, Qualified, SliceWrapped,
    TupleWrapped, UnrelatedComposite,
};
use macro_carrier::{qualification_attribute, qualification_carrier};

#[qualification_attribute]
pub trait CredentialServiceQualificationPort {
    fn qualify(&self);
    fn observe(&self) {}
}

#[qualification_attribute]
pub trait QualificationAdapter: CredentialServiceQualificationPort {}

#[diagnostic::on_unimplemented(message = "qualification unavailable")]
pub trait SafeQualificationAdapter: CredentialServiceQualificationPort {}

trait Probe {
    fn qualify(&self);
}

struct Client;

static CLIENT: Client = Client;

macro_rules! forwarding_inner {
    ($port:expr) => {
        $port.qualify()
    };
}

macro_rules! forwarding_outer {
    ($port:expr) => {
        forwarding_inner!($port)
    };
}

macro_rules! selected_method {
    ($method:ident, $port:expr) => {
        $port.$method()
    };
}

macro_rules! concrete_invoke {
    ($port:expr) => {
        $port.qualify()
    };
}

#[macro_export]
macro_rules! external {
    ($port:expr) => {
        $port.qualify()
    };
}

#[qualification_attribute]
impl CredentialServiceQualificationPort for Client {
    fn qualify(&self) {}
}

struct ProbeClient;

impl Probe for ProbeClient {
    fn qualify(&self) {}
}

struct SafeClient;

#[automatically_derived]
impl CredentialServiceQualificationPort for SafeClient {
    fn qualify(&self) {}
}

mod collision_a {
    use super::CredentialServiceQualificationPort;

    macro_rules! collision_invoke {
        ($port:expr) => {
            $port.qualify()
        };
    }

    pub(super) fn release<T: CredentialServiceQualificationPort>(port: &T) {
        collision_invoke!(port);
    }
}

mod collision_b {
    macro_rules! collision_invoke {
        ($port:expr) => {
            let _ = $port;
        };
    }

    pub(super) fn release() {
        collision_invoke!(());
    }
}

mod clean_control {
    macro_rules! probe {
        ($port:expr) => {
            $port.qualify()
        };
    }

    pub(super) fn release(port: &dyn super::Probe) {
        probe!(port);
    }
}

mod imported_before_local {
    use super::CredentialServiceQualificationPort;
    use crate::external as invoke;

    pub(super) fn release<T: CredentialServiceQualificationPort>(port: &T) {
        invoke!(port);
    }

    #[allow(unused_macros)]
    macro_rules! invoke {
        ($port:expr) => {};
    }

    pub(super) fn after<T: CredentialServiceQualificationPort>(_port: &T) {
        invoke!(_port);
    }
}

mod local_after_definition {
    use super::CredentialServiceQualificationPort;

    macro_rules! local_invoke {
        ($port:expr) => {};
    }

    pub(super) fn release<T: CredentialServiceQualificationPort>(_port: &T) {
        local_invoke!(_port);
    }
}

fn alias_call(port: &Qualified) {
    port.qualify();
}

fn borrowed_call(port: Borrowed) {
    port.qualify();
}

fn boxed_call(port: Boxed) {
    port.qualify();
}

fn tuple_call(port: TupleWrapped<'_>) {
    port.0.qualify();
}

fn array_call(port: &ArrayWrapped<'_>) {
    port[0].qualify();
}

fn slice_call(port: SliceWrapped<'_>) {
    port[0].qualify();
}

fn generic_call(port: GenericWrapped<'_>) {
    port.as_deref().unwrap().qualify();
}

fn bare_fn_call(_callback: BareFnWrapped<'_>, client: &Client) {
    client.qualify();
}

fn unrelated_composite_call(port: UnrelatedComposite<'_>) {
    let _ = port;
}

fn receive_port(_port: Option<&dyn CredentialServiceQualificationPort>) {}

fn concrete_call(client: &Client) {
    client.qualify();
}

#[inline]
#[cold]
#[track_caller]
fn inspect<T: CredentialServiceQualificationPort>(_port: &T) {}

fn macro_call<T: CredentialServiceQualificationPort>(port: &T) {
    let _ = qualification_carrier!(port);
}

fn forwarding_macro_call<T: CredentialServiceQualificationPort>(port: &T) {
    forwarding_outer!(port);
}

fn selected_qualification_call<T: CredentialServiceQualificationPort>(port: &T) {
    selected_method!(qualify, port);
}

fn selected_control_call<T: CredentialServiceQualificationPort>(port: &T) {
    selected_method!(observe, port);
}

fn concrete_macro_call(port: &Client) {
    concrete_invoke!(port);
}

fn local_macro_definition_only<T: CredentialServiceQualificationPort>(_port: &T) {
    #[allow(unused_macros)]
    macro_rules! helper {
        () => {};
    }
}

fn generic_function_item<T: CredentialServiceQualificationPort>(port: &T) {
    let action: fn(&T) = T::qualify;
    action(port);
}

fn concrete_function_item(port: &Client) {
    let action: fn(&Client) = Client::qualify;
    action(port);
}

fn test_only_statement_call<T: CredentialServiceQualificationPort>(port: &T) {
    #[cfg(test)]
    {
        port.qualify();
    }
    #[cfg_attr(not(test), cfg(test))]
    {
        port.qualify();
    }
    let _ = port;
}

qualification_carrier! {
    fn item_carrier<T: CredentialServiceQualificationPort>(port: &T) {
        port.qualify();
    }
}

#[qualification_attribute]
fn attribute_carrier<T: CredentialServiceQualificationPort>(_port: &T) {}

fn main() {
    let client = Client;
    let probe = ProbeClient;
    let _safe_client = SafeClient;
    alias_call(&client);
    borrowed_call(&CLIENT);
    boxed_call(Box::new(Client));
    tuple_call((&client,));
    array_call(&[&client]);
    slice_call(&[&client]);
    generic_call(Some(Box::new(&client)));
    bare_fn_call(receive_port, &client);
    unrelated_composite_call(("safe", [0], &[0]));
    concrete_call(&client);
    inspect(&client);
    macro_call(&client);
    forwarding_macro_call(&client);
    selected_qualification_call(&client);
    selected_control_call(&client);
    concrete_macro_call(&client);
    local_macro_definition_only(&client);
    generic_function_item(&client);
    concrete_function_item(&client);
    test_only_statement_call(&client);
    collision_a::release(&client);
    collision_b::release();
    clean_control::release(&probe);
    imported_before_local::release(&client);
    imported_before_local::after(&client);
    local_after_definition::release(&client);
    item_carrier(&client);
    attribute_carrier(&client);
}

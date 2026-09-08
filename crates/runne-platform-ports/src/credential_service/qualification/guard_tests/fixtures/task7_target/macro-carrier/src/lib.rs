use proc_macro::TokenStream;

#[proc_macro]
pub fn qualification_carrier(input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn qualification_attribute(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    item
}

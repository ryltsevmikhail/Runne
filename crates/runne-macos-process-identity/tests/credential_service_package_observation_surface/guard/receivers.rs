use std::collections::HashSet;

use super::{receiver_calls, receiver_facts};
use syn::File;

pub(super) fn count_calls(file: &File, known: &HashSet<String>) -> usize {
    let facts = receiver_facts::discover(file, known);
    receiver_calls::count(file, known, &facts)
}

//! Request-side catalog re-exports (plan-named module; implementation
//! lives in `message`/`codec`).

pub use crate::message::{MessageV1, type_name};
pub use crate::{decode_body, encode_body};

#![allow(dead_code)]

#[path = "provider_dispatch_store/fixture.rs"]
mod fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("provider_dispatch_store/part_01.inc");
include!("provider_dispatch_store/part_02.inc");
use fixture::fresh_store;

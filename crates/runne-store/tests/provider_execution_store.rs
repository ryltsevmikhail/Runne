#![allow(dead_code)]

#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/online_stream_fixture.rs"]
mod online_stream_fixture;
use online_stream_fixture::provider_taskrun_start;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("provider_execution_store/part_01.inc");
include!("provider_execution_store/part_02.inc");

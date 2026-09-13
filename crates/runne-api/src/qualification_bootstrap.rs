mod activation_prelude;
mod messages;
mod model;
mod reply_wire;
mod request_wire;
mod root_service_messages;

pub use messages::{
    BootstrapAck, BootstrapControlReply, BootstrapControlRequest, RootConsumeRequest,
    RuntimeBootstrapRequest,
};
pub use model::{
    DesktopOffer, DesktopOfferRequest, MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES,
    MAX_QUALIFICATION_BOOTSTRAP_SIGNED_PROOF_BYTES, QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN,
    QUALIFICATION_BOOTSTRAP_CONTROL_VERSION, QualificationBootstrapControlError, RunBinding,
};
pub use root_service_messages::{
    RootArmRequest, RootIssuedProof, RootPrepareRequest, RootPrepared,
};

#[cfg(test)]
mod tests;
pub use activation_prelude::{
    decode_qualification_bootstrap_prelude, encode_qualification_bootstrap_prelude,
};

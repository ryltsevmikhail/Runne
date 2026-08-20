mod containment_unavailable {
    use runne_platform::{
        AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
        ContainmentGate, ContainmentRequest, HostPlatform, NativeCertificate, RunnerIdentity,
        RuntimeProbe, StartupAttestor,
    };
    include!("containment_unavailable_parts/part_01.rs");
}

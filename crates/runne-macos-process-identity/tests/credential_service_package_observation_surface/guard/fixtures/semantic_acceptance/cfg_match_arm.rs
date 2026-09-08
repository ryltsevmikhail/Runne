fn production(flag: bool) { match flag { #[cfg(test)] true => { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }, _ => {} } }

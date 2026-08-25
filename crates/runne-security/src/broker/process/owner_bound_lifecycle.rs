impl ProcessBroker {
    /// Restores one durable handle without permitting a second native launch.
    pub fn adopt_owner_bound(
        &self,
        binding: ProcessLifecycleBindingV1,
        invocation: ProcessInvocationIdV1,
        handle: OwnedProcessHandleV1,
        intent_digest: [u8; 32],
    ) -> Result<(), OwnerBoundProcessError> {
        if intent_digest == [0; 32] {
            return Err(OwnerBoundProcessError::InvalidIntentDigest);
        }
        if handle.binding() != &binding || handle.invocation() != invocation {
            return Err(OwnerBoundProcessError::OwnershipMismatch);
        }
        let key = OwnerBoundLaunchKey::new(&binding, invocation);
        let mut active = self
            .owner_bound
            .lock()
            .map_err(|_| OwnerBoundProcessError::RegistryUnavailable)?;
        if active.contains_key(&key) {
            return Err(OwnerBoundProcessError::IntentConflict);
        }
        active.insert(
            key,
            OwnerBoundRegistryEntry::Active {
                handle,
                intent_digest,
            },
        );
        self.owner_bound_changed.notify_all();
        Ok(())
    }

    /// Launches one process only after exact containment admission.
    pub fn prepare_contained_owner_bound(
        &self,
        request: OwnerBoundProcessRequest,
        containment: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
        launcher: &dyn OwnerBoundProcessLauncher,
    ) -> Result<OwnedProcessHandleV1, OwnerBoundProcessError> {
        self.validate_spec(&request.spec)
            .map_err(|_| OwnerBoundProcessError::ProcessRejected)?;
        current_platform_admission(containment, certificate, probes).map_err(|error| {
            if matches!(error, ContainmentError::BackendUnavailable) {
                OwnerBoundProcessError::ContainmentUnavailable
            } else {
                OwnerBoundProcessError::LifecycleRejected
            }
        })?;
        self.launch_owner_bound_after_admission(request, launcher)
    }

    fn launch_owner_bound_after_admission(
        &self,
        request: OwnerBoundProcessRequest,
        launcher: &dyn OwnerBoundProcessLauncher,
    ) -> Result<OwnedProcessHandleV1, OwnerBoundProcessError> {
        let launch_nonce = new_launch_nonce()?;
        let key = OwnerBoundLaunchKey::new(&request.binding, request.invocation);
        let intent_digest = process_intent_digest(&request.spec, &request.prepared);
        let mut active = self
            .owner_bound
            .lock()
            .map_err(|_| OwnerBoundProcessError::RegistryUnavailable)?;
        loop {
            match active.get(&key) {
                Some(OwnerBoundRegistryEntry::Active {
                    handle,
                    intent_digest: existing_digest,
                }) if existing_digest == &intent_digest => return Ok(handle.clone()),
                Some(OwnerBoundRegistryEntry::Active { .. })
                | Some(OwnerBoundRegistryEntry::Stopping { .. }) => {
                    return Err(OwnerBoundProcessError::IntentConflict);
                }
                Some(OwnerBoundRegistryEntry::Uncertain {
                    handle,
                    intent_digest,
                }) => {
                    let _ = (handle, intent_digest);
                    return Err(OwnerBoundProcessError::IntentConflict);
                }
                Some(OwnerBoundRegistryEntry::Launching {
                    intent_digest: existing_digest,
                }) if existing_digest != &intent_digest => {
                    return Err(OwnerBoundProcessError::IntentConflict);
                }
                Some(OwnerBoundRegistryEntry::Launching { .. }) => {
                    active = self
                        .owner_bound_changed
                        .wait(active)
                        .map_err(|_| OwnerBoundProcessError::RegistryUnavailable)?;
                }
                None => {
                    active.insert(
                        key,
                        OwnerBoundRegistryEntry::Launching { intent_digest },
                    );
                    break;
                }
            }
        }
        drop(active);
        let observation = match launcher.launch(&OwnerBoundProcessLaunchRequest {
            spec: &request.spec,
            prepared: &request.prepared,
            binding: &request.binding,
            invocation: request.invocation,
            launch_nonce,
        }) {
            Ok(observation) => observation,
            Err(error) => {
                if let Ok(mut active) = self.owner_bound.lock() {
                    active.remove(&key);
                    self.owner_bound_changed.notify_all();
                }
                return Err(error);
            }
        };
        let handle = OwnedProcessHandleV1 {
            binding: request.binding,
            invocation: request.invocation,
            pid: observation.pid,
            start_identity: observation.start_identity,
            launch_nonce,
        };
        let mut active = match self.owner_bound.lock() {
            Ok(active) => active,
            Err(_) => {
                let _ = launcher.stop(&handle);
                return Err(OwnerBoundProcessError::RegistryUnavailable);
            }
        };
        match active.get_mut(&key) {
            Some(entry @ OwnerBoundRegistryEntry::Launching { .. }) => {
                *entry = OwnerBoundRegistryEntry::Active {
                    handle: handle.clone(),
                    intent_digest,
                };
                self.owner_bound_changed.notify_all();
            }
            Some(OwnerBoundRegistryEntry::Active { .. })
            | Some(OwnerBoundRegistryEntry::Stopping { .. })
            | Some(OwnerBoundRegistryEntry::Uncertain { .. })
            | None => {
                let _ = launcher.stop(&handle);
                return Err(OwnerBoundProcessError::LifecycleRejected);
            }
        }
        Ok(handle)
    }

    /// Stops only a live handle matching the exact expected lifecycle owner.
    pub fn stop_owner_bound(
        &self,
        binding: ProcessLifecycleBindingV1,
        invocation: ProcessInvocationIdV1,
        handle: OwnedProcessHandleV1,
        launcher: &dyn OwnerBoundProcessLauncher,
    ) -> Result<(), OwnerBoundProcessError> {
        if handle.binding() != &binding || handle.invocation() != invocation {
            return Err(OwnerBoundProcessError::OwnershipMismatch);
        }
        let mut active = self
            .owner_bound
            .lock()
            .map_err(|_| OwnerBoundProcessError::RegistryUnavailable)?;
        let key = OwnerBoundLaunchKey::new(&binding, invocation);
        let Some(expected) = active.get(&key) else {
            return Err(OwnerBoundProcessError::ProcessAlreadyStopped);
        };
        let OwnerBoundRegistryEntry::Active {
            handle: expected,
            intent_digest,
        } = expected
        else {
            return Err(OwnerBoundProcessError::LifecycleRejected);
        };
        if expected != &handle {
            return Err(OwnerBoundProcessError::OwnershipMismatch);
        }
        let intent_digest = *intent_digest;
        *active.get_mut(&key).expect("active registry entry") =
            OwnerBoundRegistryEntry::Stopping {
                handle: handle.clone(),
                intent_digest,
            };
        drop(active);
        match launcher.stop(&handle) {
            Ok(()) => {
                let mut active = self
                    .owner_bound
                    .lock()
                    .map_err(|_| OwnerBoundProcessError::RegistryUnavailable)?;
                match active.get(&key) {
                    Some(OwnerBoundRegistryEntry::Stopping {
                        handle: expected,
                        intent_digest: existing_digest,
                    }) if expected == &handle && existing_digest == &intent_digest => {
                        active.remove(&key);
                        self.owner_bound_changed.notify_all();
                        Ok(())
                    }
                    _ => Err(OwnerBoundProcessError::LifecycleRejected),
                }
            }
            Err(error) => {
                if let Ok(mut active) = self.owner_bound.lock() {
                    if let Some(entry) = active.get_mut(&key) {
                        *entry = OwnerBoundRegistryEntry::Uncertain {
                            handle,
                            intent_digest,
                        };
                    }
                    self.owner_bound_changed.notify_all();
                }
                Err(error)
            }
        }
    }
}

fn new_launch_nonce() -> Result<[u8; 16], OwnerBoundProcessError> {
    for _ in 0..4 {
        let nonce = Uuid::new_v4().into_bytes();
        if nonce != [0; 16] {
            return Ok(nonce);
        }
    }
    Err(OwnerBoundProcessError::LifecycleRejected)
}

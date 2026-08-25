impl<R: ProcessInvocationResolver> ProcessProvider for NativeProcessProvider<R> {
    fn start_process(
        &self,
        context: &ProcessCommandContext,
        command: &StartProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Self::check_principal(context.principal.as_str())?;
        let resolved = self.resolver.resolve(command)?;
        if resolved.request_digest == [0; 32]
            || resolved.spec.command_policy != CommandPolicy::StructuredOnly
        {
            return Err(ProcessHostError::Forbidden);
        }
        let invocation = *command.invocation_id.as_bytes();
        {
            let registry = self
                .registry
                .lock()
                .map_err(|_| ProcessHostError::Unavailable)?;
            if let Some(process_id) = registry.by_invocation.get(&invocation) {
                let record = registry
                    .records
                    .get(process_id)
                    .ok_or(ProcessHostError::InvariantViolation)?;
                return (record.request_digest == resolved.request_digest)
                    .then_some(record.snapshot)
                    .ok_or(ProcessHostError::Conflict);
            }
        }
        let request_digest = resolved.request_digest;
        let binding = resolved.binding.clone();
        let containment = resolved.containment.clone();
        let certificate = resolved.certificate.clone();
        let probes = resolved.probes.clone();
        let (launcher, request) = self.prepare(command, resolved)?;
        let intent_digest = request.intent_digest();
        let handle = self
            .broker
            .prepare_contained_owner_bound(
                request,
                &containment,
                certificate.as_ref(),
                &probes,
                launcher.as_ref(),
            )
            .map_err(map_owner_error)?;
        let process_id = ProcessId::from_bytes(*Uuid::now_v7().as_bytes());
        let snapshot = ProcessSnapshot {
            process_id,
            invocation_id: command.invocation_id,
            workspace_id: command.workspace_id,
            state: ProcessState::Running,
            version: 1,
            next_output_sequence: 1,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| ProcessHostError::Unavailable)?;
        let record = ProcessRecord {
            snapshot,
            task_run_id: command.task_run_id,
            attempt_id: command.attempt_id,
            principal_id: context.principal.as_str().to_owned(),
            request_digest,
            intent_digest,
            binding,
            invocation: ProcessInvocationIdV1::new(invocation)
                .map_err(|_| ProcessHostError::InvariantViolation)?,
            handle,
            launcher,
            adopted: false,
            output: Vec::new(),
        };
        if let Err(error) = self.persist_record(&record) {
            let _ = self.broker.stop_owner_bound(
                record.binding.clone(),
                record.invocation,
                record.handle.clone(),
                record.launcher.as_ref(),
            );
            return Err(error);
        }
        registry.by_invocation.insert(invocation, process_id);
        registry.records.insert(process_id, record);
        Ok(snapshot)
    }

    fn get_process(
        &self,
        context: &ProcessQueryContext,
        process_id: ProcessId,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Self::check_principal(context.principal.as_str())?;
        match self.record(process_id) {
            Ok(record) => Ok(record.snapshot()),
            Err(ProcessHostError::NotFound) => match self.re_adopt_durable(process_id)? {
                true => Ok(self.record(process_id)?.snapshot()),
                false => self.durable_snapshot(process_id),
            },
            Err(error) => Err(error),
        }
    }

    fn read_process_output(
        &self,
        context: &ProcessQueryContext,
        process_id: ProcessId,
        after_sequence: u64,
        limit: u16,
    ) -> Result<ProcessOutputPage, ProcessHostError> {
        Self::check_principal(context.principal.as_str())?;
        let mut record = match self.record(process_id) {
            Ok(record) => record,
            Err(ProcessHostError::NotFound) => {
                if self.re_adopt_durable(process_id)? {
                    self.record(process_id)?
                } else {
                    return self.durable_output(process_id, after_sequence, limit);
                }
            }
            Err(error) => return Err(error),
        };
        if matches!(record.snapshot().state, ProcessState::Running) && !record.entry().adopted {
            if !record.entry().adopted {
                Self::refresh_output(record.entry_mut())?;
                self.persist_output(record.entry())?;
            }
            self.persist_record(record.entry())?;
        }
        let chunks = record
            .entry()
            .output
            .iter()
            .filter(|chunk| chunk.sequence() > after_sequence)
            .take(usize::from(limit))
            .cloned()
            .collect();
        ProcessOutputPage::new(limit, chunks)
    }

    fn stop_process(
        &self,
        context: &ProcessCommandContext,
        command: &ExistingProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Self::check_principal(context.principal.as_str())?;
        let (binding, invocation, handle, launcher) = {
            let mut record = self.record(command.process_id)?;
            if record.snapshot().version != command.expected_version {
                return Err(ProcessHostError::Conflict);
            }
            if !matches!(
                record.snapshot().state,
                ProcessState::Running | ProcessState::Stopping
            ) {
                return Err(ProcessHostError::Conflict);
            }
            if matches!(record.snapshot().state, ProcessState::Running) {
                if !record.entry().adopted {
                    Self::refresh_output(record.entry_mut())?;
                    self.persist_output(record.entry())?;
                }
                let previous_version = record.entry().snapshot.version;
                record.entry_mut().snapshot.state = ProcessState::Stopping;
                record.entry_mut().snapshot.version = record
                    .entry()
                    .snapshot
                    .version
                    .checked_add(1)
                    .ok_or(ProcessHostError::InvariantViolation)?;
                if let Err(error) = self.persist_record(record.entry()) {
                    record.entry_mut().snapshot.state = ProcessState::Running;
                    record.entry_mut().snapshot.version = previous_version;
                    return Err(error);
                }
            }
            (
                record.entry().binding.clone(),
                record.entry().invocation,
                record.entry().handle.clone(),
                Arc::clone(&record.entry().launcher),
            )
        };
        self.broker
            .stop_owner_bound(binding, invocation, handle, launcher.as_ref())
            .map_err(map_owner_error)?;
        let mut record = self.record(command.process_id)?;
        record.entry_mut().snapshot.state = ProcessState::Exited;
        record.entry_mut().snapshot.version = record
            .entry()
            .snapshot
            .version
            .checked_add(1)
            .ok_or(ProcessHostError::InvariantViolation)?;
        self.persist_record(record.entry())?;
        Ok(record.snapshot())
    }
}

struct ProcessRecordGuard<'a> {
    registry: std::sync::MutexGuard<'a, NativeProcessRegistry>,
    process_id: ProcessId,
}

impl ProcessRecordGuard<'_> {
    fn entry(&self) -> &ProcessRecord {
        self.registry
            .records
            .get(&self.process_id)
            .expect("record checked")
    }
    fn entry_mut(&mut self) -> &mut ProcessRecord {
        self.registry
            .records
            .get_mut(&self.process_id)
            .expect("record checked")
    }
    fn snapshot(&self) -> ProcessSnapshot {
        self.entry().snapshot
    }
}

fn sanitize_output(raw: Vec<CapturedOutput>) -> Result<Vec<ProcessOutputChunk>, ProcessHostError> {
    raw.into_iter()
        .filter_map(|chunk| {
            let text = String::from_utf8_lossy(&chunk.bytes)
                .chars()
                .filter(|character| {
                    (!character.is_control() || matches!(character, '\n' | '\t'))
                        && !matches!(
                            *character,
                            '\u{061c}'
                                | '\u{200e}'
                                | '\u{200f}'
                                | '\u{202a}'..='\u{202e}'
                                | '\u{2066}'..='\u{2069}'
                        )
                })
                .collect::<String>();
            (!text.is_empty()).then_some((chunk.stderr, text))
        })
        .enumerate()
        .map(|(index, (stderr, text))| {
            ProcessOutputChunk::new(
                u64::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ProcessHostError::InvariantViolation)?,
                if stderr {
                    ProcessOutputStream::Stderr
                } else {
                    ProcessOutputStream::Stdout
                },
                text,
            )
        })
        .collect()
}

fn map_owner_error(error: OwnerBoundProcessError) -> ProcessHostError {
    match error {
        OwnerBoundProcessError::ContainmentUnavailable
        | OwnerBoundProcessError::RegistryUnavailable
        | OwnerBoundProcessError::LifecycleRejected => ProcessHostError::Unavailable,
        OwnerBoundProcessError::OwnershipMismatch
        | OwnerBoundProcessError::IntentConflict
        | OwnerBoundProcessError::ProcessAlreadyStopped => ProcessHostError::Conflict,
        OwnerBoundProcessError::ProcessRejected
        | OwnerBoundProcessError::PreparedInvocationInvalid
        | OwnerBoundProcessError::InvalidInvocationIdentity
        | OwnerBoundProcessError::InvalidIntentDigest
        | OwnerBoundProcessError::InvalidLaunchIdentity => ProcessHostError::Forbidden,
    }
}

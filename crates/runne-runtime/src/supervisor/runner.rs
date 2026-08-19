
// ── run_supervisor ──────────────────────────────────────────────────────────

pub(crate) async fn run_supervisor<E, U, I>(
    mut ingress_rx: mpsc::Receiver<AdmittedRequest>,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    gate: Arc<AdmissionGate>,
    config: RuntimeConfig,
    cancel: CancellationToken,
    service: Arc<TaskRunService<E, U, I>>,
    conversation_service: Option<Arc<dyn ConversationTextCommandService>>,
    provider_service: Option<Arc<dyn CanonicalProviderExecutionService>>,
    drain_complete_tx: oneshot::Sender<ShutdownOutcome>,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let mut registry = WorkerRegistry::new(
        config,
        cancel.clone(),
        service.clone(),
        conversation_service,
        provider_service,
    );
    let mut draining = false;
    let mut ingress_open = true;
    let mut control_open = true;
    let mut shutdown_ack: Option<oneshot::Sender<ShutdownOutcome>> = None;
    let mut rejected_commands: usize = 0;

    crate::controller::trace_shutdown_phase(format_args!("phase=supervisor_select_started"));
    loop {
        tokio::select! {
            biased;

            cmd = control_rx.recv(), if control_open => {
                match cmd {
                    Some(ControlCommand::Shutdown { mode, ack }) => {
                        crate::controller::trace_shutdown_phase(format_args!(
                            "phase=command_received mode={mode:?} active_workers={} join_tasks={}",
                            registry.worker_count(),
                            registry.join_set.len(),
                        ));
                        crate::controller::trace_shutdown_phase(format_args!(
                            "phase=gate_drain_started"
                        ));
                        gate.drain().await;
                        crate::controller::trace_shutdown_phase(format_args!(
                            "phase=gate_drained active_workers={} join_tasks={}",
                            registry.worker_count(),
                            registry.join_set.len(),
                        ));
                        gate.close();
                        draining = true;
                        shutdown_ack = Some(ack);
                        ingress_rx.close();
                        match mode {
                            ShutdownMode::Graceful { .. } => {
                                while let Ok(admitted) = ingress_rx.try_recv() {
                                    dispatch_admitted(
                                        admitted,
                                        &mut registry,
                                        Arc::clone(&service),
                                    );
                                }
                                registry.close_all_workers();
                            }
                            ShutdownMode::Immediate { .. } => {
                                while let Ok(admitted) = ingress_rx.try_recv() {
                                    reject_request(admitted.request);
                                    rejected_commands += 1;
                                }
                                cancel.cancel();
                            }
                        }
                        ingress_open = false;
                        crate::controller::trace_shutdown_phase(format_args!(
                            "phase=registry_wait_started active_workers={} join_tasks={} rejected_commands={rejected_commands}",
                            registry.worker_count(),
                            registry.join_set.len(),
                        ));
                    }
                    None => {
                        control_open = false;
                        draining = true;
                    }
                }
            }

            msg = ingress_rx.recv(), if ingress_open => {
                match msg {
                    Some(admitted) => {
                        if draining {
                            reject_request(admitted.request);
                            rejected_commands += 1;
                            continue;
                        }
                        dispatch_admitted(admitted, &mut registry, Arc::clone(&service));
                    }
                    None => {
                        ingress_open = false;
                        draining = true;
                    }
                }
            }

            exit = registry.join_set.join_next(), if !registry.join_set.is_empty() => {
                match exit {
                    Some(Ok(RuntimeTaskExit::Worker(we))) => { registry.remove_worker(&we); }
                    Some(Ok(RuntimeTaskExit::Create { reply, outcome, .. })) => {
                        let _ = reply.send(outcome);
                    }
                    Some(Ok(RuntimeTaskExit::ConversationText { reply, outcome })) => {
                        let _ = reply.send(outcome);
                    }
                    Some(Ok(RuntimeTaskExit::CanonicalProvider { reply, outcome, lease })) => {
                        let _ = reply.send(outcome);
                        drop(lease);
                    }
                    _ => {}
                }
                if draining {
                    crate::controller::trace_shutdown_phase(format_args!(
                        "phase=registry_join_completed active_workers={} join_tasks={} rejected_commands={rejected_commands}",
                        registry.worker_count(),
                        registry.join_set.len(),
                    ));
                }
            }

            else => break,
        }

        if draining && registry.worker_count() == 0 && registry.join_set.is_empty() {
            let outcome = ShutdownOutcome::Quiesced;
            if let Some(ack) = shutdown_ack.take() {
                let ack_sent = ack.send(outcome.clone()).is_ok();
                crate::controller::trace_shutdown_phase(format_args!(
                    "phase=ack_sent outcome={} active_workers={} join_tasks={} rejected_commands={rejected_commands}",
                    if ack_sent { "sent" } else { "receiver_closed" },
                    registry.worker_count(),
                    registry.join_set.len(),
                ));
            }
            let _ = drain_complete_tx.send(outcome);
            return;
        }
    }

    let outcome = ShutdownOutcome::Incomplete {
        active_workers: registry.worker_count(),
        active_blocking_ops: 0,
        rejected_commands,
    };
    if let Some(ack) = shutdown_ack.take() {
        let ack_sent = ack.send(outcome.clone()).is_ok();
        crate::controller::trace_shutdown_phase(format_args!(
            "phase=incomplete_ack_sent outcome={} active_workers={} join_tasks={} rejected_commands={rejected_commands}",
            if ack_sent { "sent" } else { "receiver_closed" },
            registry.worker_count(),
            registry.join_set.len(),
        ));
    }
    let _ = drain_complete_tx.send(outcome);
}

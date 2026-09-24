
// ── reject_request ──────────────────────────────────────────────────────────

fn reject_request(request: RuntimeRequest) {
    match request {
        RuntimeRequest::Create { reply, .. }
        | RuntimeRequest::Submit { reply, .. }
        | RuntimeRequest::SubmitLegacy { reply, .. }
        | RuntimeRequest::Queue { reply, .. }
        | RuntimeRequest::Admit { reply, .. }
        | RuntimeRequest::StartAttempt { reply, .. }
        | RuntimeRequest::Cancel { reply, .. }
        | RuntimeRequest::Complete { reply, .. } => {
            let _ = reply.send(Err(RuntimeError::RuntimeClosed));
        }
        RuntimeRequest::BeginConversationText { reply, .. }
        | RuntimeRequest::FinishConversationText { reply, .. } => {
            let _ = reply.send(Err(RuntimeError::RuntimeClosed));
        }
        RuntimeRequest::CanonicalProviderExecution { reply, .. } => {
            let _ = reply.send(Err(CanonicalProviderExecutionError::Unavailable));
        }
    }
}

// ── route_to_worker ─────────────────────────────────────────────────────────

fn route_to_worker<E, U, I>(
    taskrun_id: TaskRunId,
    per_run: PerRunRequest,
    lease: InFlightLease,
    registry: &mut WorkerRegistry<E, U, I>,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let handle = match registry.get_or_spawn(taskrun_id) {
        Ok(h) => h,
        Err(e) => {
            let reply = extract_reply(per_run);
            let _ = reply.send(Err(e));
            return;
        }
    };

    let msg = AdmittedPerRunRequest {
        request: per_run,
        lease,
    };

    match handle.sender.try_send(msg) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(m)) => {
            let reply = extract_reply(m.request);
            let _ = reply.send(Err(RuntimeError::Backpressure {
                queue: QueueKind::TaskRun,
            }));
        }
        Err(mpsc::error::TrySendError::Closed(m)) => {
            // Stale handle — retry once with fresh spawn
            registry.remove_worker(&WorkerExit {
                taskrun_id,
                generation: handle.generation,
            });
            let handle2 = match registry.spawn_worker(taskrun_id) {
                Ok(h) => h,
                Err(e) => {
                    let reply = extract_reply(m.request);
                    let _ = reply.send(Err(e));
                    return;
                }
            };
            let msg2 = AdmittedPerRunRequest {
                request: m.request,
                lease: m.lease,
            };
            match handle2.sender.try_send(msg2) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(m2)) => {
                    let reply = extract_reply(m2.request);
                    let _ = reply.send(Err(RuntimeError::Backpressure {
                        queue: QueueKind::TaskRun,
                    }));
                }
                Err(mpsc::error::TrySendError::Closed(m2)) => {
                    let reply = extract_reply(m2.request);
                    let _ = reply.send(Err(RuntimeError::RuntimeClosed));
                }
            }
        }
    }
}

// ── dispatch_admitted ───────────────────────────────────────────────────────

fn dispatch_admitted<E, U, I>(
    admitted: AdmittedRequest,
    registry: &mut WorkerRegistry<E, U, I>,
    service: Arc<TaskRunService<E, U, I>>,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let AdmittedRequest { request, lease } = admitted;

    match request {
        RuntimeRequest::Create {
            context,
            input,
            reply,
        } => {
            registry.spawn_create_task(context, input, service, reply);
            drop(lease);
        }
        RuntimeRequest::Submit {
            context,
            input,
            reply,
        } => {
            registry.spawn_submit_task(context, input, service, reply);
            drop(lease);
        }
        RuntimeRequest::SubmitLegacy { context, input, reply } => {
            registry.spawn_submit_legacy_task(context, input, service, reply);
            drop(lease);
        }
        RuntimeRequest::Queue {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Queue {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::Admit {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Admit {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::StartAttempt {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::StartAttempt {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::Cancel {
            context,
            input,
            reply,
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Cancel {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::Complete {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Complete {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::BeginConversationText {
            context,
            input,
            reply,
        } => {
            registry.spawn_conversation_text_task(
                ConversationTextCall::Begin { context, input },
                reply,
            );
            drop(lease);
        }
        RuntimeRequest::FinishConversationText {
            context,
            input,
            reply,
        } => {
            registry.spawn_conversation_text_task(
                ConversationTextCall::Finish { context, input },
                reply,
            );
            drop(lease);
        }
        RuntimeRequest::CanonicalProviderExecution { job, reply } => {
            registry.spawn_canonical_provider_task(job, reply, lease);
        }
    }
}

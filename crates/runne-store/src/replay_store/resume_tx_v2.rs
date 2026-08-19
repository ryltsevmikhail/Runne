fn resume_session_from_internal_facts(
    conn: &mut Connection,
    request: InternalResumeFacts,
    lineage_id: &EventLogLineageId,
    server_secret: &[u8; 32],
    delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
) -> Result<(ReplaySession, Vec<ReplayEvent>, ReplayEvent, runne_application::ports::ReplayAcceptedPromotionV2), ReplayError> {
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| ReplayError::Storage(format!("resume transaction: {error}")))?;
    let inventory = retained_inventory(&tx)?;
    let retained_floor = inventory
        .events
        .first()
        .map(|event| event.global_position)
        .ok_or_else(|| {
            ReplayError::Integrity("V2 baseline retained floor is unavailable".to_owned())
        })?;
    let high_water = inventory
        .events
        .last()
        .map(|event| event.global_position)
        .ok_or_else(|| {
            ReplayError::Integrity("V2 baseline high water is unavailable".to_owned())
        })?;
    let (baseline_event, accepted) = validate_v2_baseline(
        &tx,
        &inventory,
        &request,
        lineage_id,
        server_secret,
        retained_floor,
        high_water,
    )?;
    let session_id = ReplayStore::generate_session_id();
    let high_water_ref = build_high_water_ref(
        &request.authority_id,
        Some(retained_floor),
        high_water,
        server_secret,
        &session_id,
    );
    let mut events = read_v2_resume_events(&tx, &request, high_water)?;
    let more_than_page = events.len() > 100;
    events.truncate(100);
    let selected_len = events.len();
    let mut prefix = ReplaySession {
        session_id,
        principal_id: request.principal_id.clone(),
        session_generation: request.session_generation,
        authority_id: request.authority_id,
        authorization_epoch: request.authorization_epoch,
        aggregate_type: request.aggregate_type,
        aggregate_id: request.aggregate_id,
        retained_floor: Some(retained_floor),
        retention_generation: i64::try_from(RETENTION_GENERATION)
            .map_err(|_| ReplayError::Integrity("retention generation overflow".to_owned()))?,
        high_water_position: high_water,
        next_page_position: None,
        last_delivered_position: Some(request.baseline_global_position),
        last_acked_position: Some(request.baseline_global_position),
        state: ReplayState::CatchingUp,
        high_water_ref,
        catch_up_completion: None,
        live_delivery_id: None,
        created_at: String::new(),
    };
    let mut authorized = 0;
    for (index, event) in events.iter().enumerate() {
        prefix.last_delivered_position = Some(event.global_position);
        prefix.next_page_position = if index + 1 < selected_len || more_than_page {
            Some(event.global_position.checked_add(1).ok_or_else(|| {
                ReplayError::Integrity("V2 resume global position overflow".to_owned())
            })?)
        } else {
            None
        };
        match delivery_guard.inspect_event(&prefix, event) {
            Ok(()) => authorized = index + 1,
            Err(ReplayError::SensitivityDenied) if authorized > 0 => break,
            Err(error) => return Err(error),
        }
    }
    events.truncate(authorized);
    let has_more = more_than_page || authorized < selected_len;
    let last_delivered = events
        .last()
        .map(|event| event.global_position)
        .or(Some(request.baseline_global_position));
    let next_page = if has_more {
        Some(
            last_delivered
                .ok_or(ReplayError::SensitivityDenied)?
                .checked_add(1)
                .ok_or_else(|| {
                    ReplayError::Integrity("V2 resume global position overflow".to_owned())
                })?,
        )
    } else {
        None
    };
    let candidate = ReplaySession {
        next_page_position: next_page,
        last_delivered_position: last_delivered,
        ..prefix
    };
    let mut transaction = Some(tx);
    let persisted = delivery_guard.mutate_session_admission(&candidate, &events, &mut || {
        let tx = transaction.take().ok_or_else(|| {
            ReplayError::Integrity("V2 replay admission mutation was invoked twice".to_owned())
        })?;
        insert_v2_resume_session(&tx, &candidate)?;
        let persisted = read_v2_resume_session(&tx, &candidate.session_id)?;
        tx.commit()
            .map_err(|error| ReplayError::Storage(format!("commit V2 resume: {error}")))?;
        Ok(persisted)
    })?;
    Ok((persisted, events, baseline_event, accepted))
}

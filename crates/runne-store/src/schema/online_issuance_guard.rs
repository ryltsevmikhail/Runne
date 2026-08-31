use std::sync::{Arc, Mutex};

use rusqlite::functions::{Context, FunctionFlags};

const ONLINE_ISSUANCE_GUARD_FUNCTION: &str = "runne_online_issuance_guard";

#[derive(Clone)]
pub(crate) struct OnlineIssuanceGuard {
    current: Arc<Mutex<Option<OnlineIssuanceBinding>>>,
}

#[derive(PartialEq, Eq)]
struct OnlineIssuanceBinding {
    attempt_id: [u8; 16],
    provider_id: String,
    authority_id: [u8; 16],
    authority_revision: i64,
    issued_at: i64,
}

pub(crate) struct OnlineIssuanceGuardScope {
    current: Arc<Mutex<Option<OnlineIssuanceBinding>>>,
}

impl OnlineIssuanceGuard {
    pub(crate) fn restore(&self, connection: &Connection) -> SqliteResult<()> {
        let current = Arc::clone(&self.current);
        connection.create_scalar_function(
            ONLINE_ISSUANCE_GUARD_FUNCTION,
            5,
            FunctionFlags::SQLITE_UTF8,
            move |context: &Context<'_>| online_issuance_guard_matches(&current, context),
        )
    }

    pub(crate) fn enable(
        &self,
        attempt_id: [u8; 16],
        provider_id: &str,
        authority_id: [u8; 16],
        authority_revision: i64,
        issued_at: i64,
    ) -> SqliteResult<OnlineIssuanceGuardScope> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if current.is_some() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        *current = Some(OnlineIssuanceBinding {
            attempt_id,
            provider_id: provider_id.to_owned(),
            authority_id,
            authority_revision,
            issued_at,
        });
        Ok(OnlineIssuanceGuardScope {
            current: Arc::clone(&self.current),
        })
    }
}

impl Drop for OnlineIssuanceGuardScope {
    fn drop(&mut self) {
        if let Ok(mut current) = self.current.lock() {
            *current = None;
        }
    }
}

fn install_online_issuance_guard(connection: &Connection) -> SqliteResult<OnlineIssuanceGuard> {
    let guard = OnlineIssuanceGuard {
        current: Arc::new(Mutex::new(None)),
    };
    guard.restore(connection)?;
    Ok(guard)
}

fn online_issuance_guard_matches(
    current: &Arc<Mutex<Option<OnlineIssuanceBinding>>>,
    context: &Context<'_>,
) -> SqliteResult<bool> {
    let attempt_id: [u8; 16] = context
        .get::<Vec<u8>>(0)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let provider_id = context.get::<String>(1)?;
    let authority_id: [u8; 16] = context
        .get::<Vec<u8>>(2)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let authority_revision = context.get::<i64>(3)?;
    let issued_at = context.get::<i64>(4)?;
    let Ok(current) = current.lock() else {
        return Ok(false);
    };
    Ok(current.as_ref().is_some_and(|expected| {
        expected.attempt_id == attempt_id
            && expected.provider_id == provider_id
            && expected.authority_id == authority_id
            && expected.authority_revision == authority_revision
            && expected.issued_at == issued_at
    }))
}

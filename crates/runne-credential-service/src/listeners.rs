use std::{
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use runne_credential_service_core::CredentialServiceCore;
use runne_macos_xpc::{
    CredentialServiceEndpointConfiguration, CredentialServiceRequestHandler,
    CredentialServiceXpcError, CredentialServiceXpcListener,
};
use runne_provider::CredentialServiceEndpointRole as DomainRole;
use zeroize::Zeroizing;

use crate::keychain::KeychainBackend;

const IDLE_TIMEOUT_MILLIS: u64 = 30_000;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

struct ServiceState {
    core: CredentialServiceCore,
}

struct ServiceHandler {
    state: Mutex<ServiceState>,
    in_flight: AtomicUsize,
    last_activity: Mutex<Instant>,
}

impl ServiceHandler {
    fn new() -> Result<Self, CredentialServiceXpcError> {
        Ok(Self {
            state: Mutex::new(ServiceState {
                core: CredentialServiceCore::new()
                    .map_err(|_| CredentialServiceXpcError::Unavailable)?,
            }),
            in_flight: AtomicUsize::new(0),
            last_activity: Mutex::new(Instant::now()),
        })
    }

    fn activity(&self, now: u64) -> Result<(bool, usize, Duration), CredentialServiceXpcError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialServiceXpcError::Unavailable)?;
        Ok((
            state.core.poll(now).prevents_idle(),
            self.in_flight.load(Ordering::Acquire),
            self.last_activity
                .lock()
                .map_err(|_| CredentialServiceXpcError::Unavailable)?
                .elapsed(),
        ))
    }
}

impl CredentialServiceRequestHandler for ServiceHandler {
    fn handle(
        &self,
        role: runne_macos_xpc::CredentialServiceEndpointRole,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let _guard = InFlightGuard(&self.in_flight);
        let now = unix_millis()?;
        *self
            .last_activity
            .lock()
            .map_err(|_| CredentialServiceXpcError::Unavailable)? = Instant::now();
        match role {
            runne_macos_xpc::CredentialServiceEndpointRole::Desktop => {
                self.handle_desktop(&request, now)
            }
            runne_macos_xpc::CredentialServiceEndpointRole::Runtime => {
                self.handle_runtime(&request, now)
            }
            runne_macos_xpc::CredentialServiceEndpointRole::Writer => {
                self.handle_writer(&request, now)
            }
        }
    }
}

impl ServiceHandler {
    fn handle_desktop(
        &self,
        request: &[u8],
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialServiceXpcError::Unavailable)?;
        let response = state
            .core
            .challenge(DomainRole::Desktop, request, now)
            .map_or_else(
                |_| {
                    state
                        .core
                        .accept_registration_install(DomainRole::Desktop, request, now)
                        .map(|(_, ack)| Zeroizing::new(ack.into_bytes()))
                        .map_err(|_| CredentialServiceXpcError::Invalidated)
                },
                |reply| Ok(reply.into_transport_bytes()),
            );
        drop(state);
        response
    }

    fn handle_runtime(
        &self,
        request: &[u8],
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialServiceXpcError::Unavailable)?;
        let response = state
            .core
            .handle_runtime(DomainRole::Runtime, request, now, |effect| {
                KeychainBackend::read(&effect)
            })
            .map_or_else(
                |_| Err(CredentialServiceXpcError::Invalidated),
                |reply| Ok(reply.into_transport_bytes()),
            );
        drop(state);
        response
    }

    fn handle_writer(
        &self,
        request: &[u8],
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialServiceXpcError::Unavailable)?;
        let response = state
            .core
            .handle_writer(DomainRole::Writer, request, now, KeychainBackend::mutate)
            .map_or_else(
                |_| Err(CredentialServiceXpcError::Invalidated),
                |reply| Ok(reply.into_transport_bytes()),
            );
        drop(state);
        response
    }
}

struct InFlightGuard<'a>(&'a AtomicUsize);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct IdlePolicy {
    timeout: Duration,
}

impl IdlePolicy {
    const fn new(timeout_millis: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_millis),
        }
    }

    fn should_stop(
        &self,
        idle: Duration,
        active_connections: usize,
        in_flight: usize,
        core_prevents_idle: bool,
    ) -> bool {
        idle >= self.timeout && active_connections == 0 && in_flight == 0 && !core_prevents_idle
    }
}

fn serve(
    configurations: &[CredentialServiceEndpointConfiguration; 3],
) -> Result<(), CredentialServiceXpcError> {
    let expected = [
        runne_macos_xpc::CredentialServiceEndpointRole::Desktop,
        runne_macos_xpc::CredentialServiceEndpointRole::Runtime,
        runne_macos_xpc::CredentialServiceEndpointRole::Writer,
    ];
    if configurations
        .iter()
        .map(CredentialServiceEndpointConfiguration::role)
        .ne(expected)
    {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let handler = Arc::new(ServiceHandler::new()?);
    let handler_api: Arc<dyn CredentialServiceRequestHandler> = handler.clone();
    let listeners = configurations
        .iter()
        .map(|configuration| CredentialServiceXpcListener::bind(configuration, handler_api.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = IdlePolicy::new(IDLE_TIMEOUT_MILLIS);
    loop {
        std::thread::sleep(POLL_INTERVAL);
        let now = unix_millis()?;
        let (core_active, in_flight, idle) = handler.activity(now)?;
        let connections = listeners
            .iter()
            .map(CredentialServiceXpcListener::active_connections)
            .sum();
        if policy.should_stop(idle, connections, in_flight, core_active) {
            for listener in &listeners {
                listener.close_admission();
            }
            let now = unix_millis()?;
            let (core_active, in_flight, idle) = handler.activity(now)?;
            let connections = listeners
                .iter()
                .map(CredentialServiceXpcListener::active_connections)
                .sum();
            if policy.should_stop(idle, connections, in_flight, core_active) {
                for listener in &listeners {
                    listener.invalidate();
                }
                return Ok(());
            }
            for listener in &listeners {
                listener.reopen_admission();
            }
        }
    }
}

pub fn run() -> ExitCode {
    let Ok(configurations) = crate::package_identity::installed_configurations() else {
        return ExitCode::FAILURE;
    };
    if serve(&configurations).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn unix_millis() -> Result<u64, CredentialServiceXpcError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CredentialServiceXpcError::Unavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| CredentialServiceXpcError::Unavailable)
}

#[cfg(test)]
mod tests;

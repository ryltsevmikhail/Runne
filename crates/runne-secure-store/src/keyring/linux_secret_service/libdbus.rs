//! Production libdbus transport for the Secret Service facade.
//!
//! The bus is opened from one explicit, pre-validated address (the deterministic
//! `/run/user/<uid>/bus` derivation shared with the P0 writer spawn profile) —
//! never from ambient autolaunch or renderer state. Every proxy destination is
//! supplied by the facade (bus daemon for owner resolution, the resolved
//! unique name for all Secret Service calls including `OpenSession`).

use std::collections::HashMap;
use std::time::Duration;

use dbus::Path;
use dbus::arg::{RefArg, Variant};
use dbus::blocking::Connection;
use dbus::channel::Channel;

use super::dh_session::WireSecret;
use super::port::{
    PeerCredentials, SecretServiceBus, SsBusError, SsMutationOutcome, SsSearchOutcome,
};

const BUS_DAEMON: &str = "org.freedesktop.DBus";
const BUS_DAEMON_PATH: &str = "/org/freedesktop/DBus";
const SECRETS_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const NAME_HAS_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

type SecretStruct<'a> = (Path<'a>, Vec<u8>, Vec<u8>, String);

/// libdbus-backed transport bound to one validated bus address.
pub struct LibdbusSecretServiceBus {
    connection: Connection,
}

impl LibdbusSecretServiceBus {
    /// Opens one private connection to the strictly derived session-bus
    /// address. The address is validated (scheme, canonical path, own euid,
    /// socket ownership and type) BEFORE any connect attempt; this
    /// constructor never consults process environment or autolaunch.
    pub fn connect(derived_address: &str) -> Result<Self, SsBusError> {
        let socket_path = validate_derived_session_bus_address(derived_address)?;
        probe_session_bus_socket(&socket_path)?;
        let mut channel = Channel::open_private(derived_address).map_err(transport)?;
        channel.register().map_err(transport)?;
        Ok(Self {
            connection: Connection::from(channel),
        })
    }
}

/// Accepts exactly `unix:path=/run/user/<euid>/bus` for the supplied euid.
/// Everything else — tcp:, unixexec:, abstract sockets, relative or foreign
/// paths, extra address parameters — is rejected before any connection.
pub fn validate_derived_session_bus_address(address: &str) -> Result<String, SsBusError> {
    let path = address
        .strip_prefix("unix:path=")
        .ok_or(SsBusError::Transport)?;
    if address.matches("unix:").count() != 1 || address.contains(';') || address.contains(',') {
        return Err(SsBusError::Transport);
    }
    let expected = derived_session_bus_address();
    if path != expected {
        return Err(SsBusError::Transport);
    }
    Ok(path.to_owned())
}

/// Deterministic euid-derived session-bus path (the P0 derivation, no env).
pub fn derived_session_bus_address() -> String {
    use std::os::unix::fs::MetadataExt;
    let euid = std::fs::metadata("/proc/self").map_or(u32::MAX, |metadata| metadata.uid());
    format!("/run/user/{euid}/bus")
}

fn probe_session_bus_socket(path: &str) -> Result<(), SsBusError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::metadata(path).map_err(|_| SsBusError::Transport)?;
    if !metadata.file_type().is_socket() {
        return Err(SsBusError::Transport);
    }
    let euid = std::fs::metadata("/proc/self").map_or(u32::MAX, |metadata| metadata.uid());
    if metadata.uid() != euid {
        return Err(SsBusError::Transport);
    }
    Ok(())
}

impl SecretServiceBus for LibdbusSecretServiceBus {
    fn name_owner(&mut self, well_known: &str) -> Result<Option<String>, SsBusError> {
        let proxy = self
            .connection
            .with_proxy(BUS_DAEMON, BUS_DAEMON_PATH, CALL_TIMEOUT);
        match proxy.method_call(BUS_DAEMON, "GetNameOwner", (well_known,)) {
            Ok((owner,)) => Ok(Some(owner)),
            Err(error) if error.name() == Some(NAME_HAS_NO_OWNER) => Ok(None),
            Err(_) => Err(SsBusError::Transport),
        }
    }

    fn peer_credentials(&mut self, name: &str) -> Result<PeerCredentials, SsBusError> {
        let proxy = self
            .connection
            .with_proxy(BUS_DAEMON, BUS_DAEMON_PATH, CALL_TIMEOUT);
        let (pid,): (u32,) = proxy
            .method_call(BUS_DAEMON, "GetConnectionUnixProcessID", (name,))
            .map_err(transport)?;
        let (uid,): (u32,) = proxy
            .method_call(BUS_DAEMON, "GetConnectionUnixUser", (name,))
            .map_err(transport)?;
        Ok(PeerCredentials { pid, uid })
    }

    fn open_session(
        &mut self,
        dest: &str,
        algorithm: &str,
        public_key: Vec<u8>,
    ) -> Result<(Vec<u8>, String), SsBusError> {
        let proxy = self.connection.with_proxy(dest, SECRETS_PATH, CALL_TIMEOUT);
        let input = Variant(Box::new(public_key) as Box<dyn RefArg>);
        let (output, session): (Variant<Box<dyn RefArg>>, Path<'static>) = proxy
            .method_call(SERVICE_INTERFACE, "OpenSession", (algorithm, input))
            .map_err(transport)?;
        let server_key = dbus::arg::cast::<Vec<u8>>(&output.0).ok_or(SsBusError::Transport)?;
        Ok((server_key.clone(), session.to_string()))
    }

    fn read_alias(&mut self, dest: &str, alias: &str) -> Result<Option<String>, SsBusError> {
        let proxy = self.connection.with_proxy(dest, SECRETS_PATH, CALL_TIMEOUT);
        let (path,): (Path<'static>,) = proxy
            .method_call(SERVICE_INTERFACE, "ReadAlias", (alias,))
            .map_err(transport)?;
        Ok((path.as_str() != Some("/")).then(|| path.to_string()))
    }

    fn search_items(
        &mut self,
        dest: &str,
        attributes: &[(String, String)],
    ) -> Result<SsSearchOutcome, SsBusError> {
        let attributes: HashMap<&str, &str> = attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let proxy = self.connection.with_proxy(dest, SECRETS_PATH, CALL_TIMEOUT);
        let (unlocked, locked): (Vec<Path<'static>>, Vec<Path<'static>>) = proxy
            .method_call(SERVICE_INTERFACE, "SearchItems", (attributes,))
            .map_err(transport)?;
        Ok(SsSearchOutcome {
            unlocked: unlocked.into_iter().map(|path| path.to_string()).collect(),
            locked: locked.into_iter().map(|path| path.to_string()).collect(),
        })
    }

    fn get_secret(
        &mut self,
        dest: &str,
        session_path: &str,
        item: &str,
    ) -> Result<WireSecret, SsBusError> {
        let proxy = self.connection.with_proxy(dest, item, CALL_TIMEOUT);
        let secret_path = Path::from(session_path);
        let (secret,): (SecretStruct<'_>,) = proxy
            .method_call(ITEM_INTERFACE, "GetSecret", (secret_path,))
            .map_err(transport)?;
        Ok(WireSecret {
            session_path: secret.0.to_string(),
            iv: secret.1,
            data: secret.2,
            mime: secret.3,
        })
    }

    fn set_item_secret(
        &mut self,
        dest: &str,
        item: &str,
        secret: WireSecret,
    ) -> Result<SsMutationOutcome, SsBusError> {
        let wire: SecretStruct<'_> = (
            Path::from(secret.session_path.as_str()),
            secret.iv,
            secret.data,
            secret.mime,
        );
        let proxy = self.connection.with_proxy(dest, item, CALL_TIMEOUT);
        let (): () = proxy
            .method_call(ITEM_INTERFACE, "SetSecret", (wire,))
            .map_err(transport)?;
        Ok(SsMutationOutcome::Done)
    }

    fn create_item(
        &mut self,
        dest: &str,
        collection: &str,
        label: &str,
        attributes: &[(String, String)],
        secret: WireSecret,
        replace: bool,
    ) -> Result<(Option<String>, SsMutationOutcome), SsBusError> {
        let mut properties: HashMap<String, Variant<Box<dyn RefArg>>> = HashMap::new();
        let attribute_map: HashMap<String, String> = attributes.iter().cloned().collect();
        properties.insert(
            "org.freedesktop.Secret.Item.Label".to_owned(),
            Variant(Box::new(label.to_owned()) as Box<dyn RefArg>),
        );
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes".to_owned(),
            Variant(Box::new(attribute_map) as Box<dyn RefArg>),
        );
        let wire: SecretStruct<'_> = (
            Path::from(secret.session_path.as_str()),
            secret.iv,
            secret.data,
            secret.mime,
        );
        let proxy = self.connection.with_proxy(dest, collection, CALL_TIMEOUT);
        let (item, prompt): (Path<'static>, Path<'static>) = proxy
            .method_call(
                COLLECTION_INTERFACE,
                "CreateItem",
                (properties, wire, replace),
            )
            .map_err(transport)?;
        if prompt.as_str() != Some("/") {
            return Ok((None, SsMutationOutcome::PromptRequired));
        }
        Ok((
            (item.as_str() != Some("/")).then(|| item.to_string()),
            SsMutationOutcome::Done,
        ))
    }

    fn delete_item(&mut self, dest: &str, item: &str) -> Result<SsMutationOutcome, SsBusError> {
        let proxy = self.connection.with_proxy(dest, item, CALL_TIMEOUT);
        let (prompt,): (Path<'static>,) = proxy
            .method_call(ITEM_INTERFACE, "Delete", ())
            .map_err(transport)?;
        Ok(if prompt.as_str() == Some("/") {
            SsMutationOutcome::Done
        } else {
            SsMutationOutcome::PromptRequired
        })
    }
}

fn transport(_: dbus::Error) -> SsBusError {
    SsBusError::Transport
}

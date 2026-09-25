use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
type PersistedNodeRegistration = (i64, i64, String, String, String, i64, i64, i64);
const MAX_NODE_TTL_MS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxNodeDescriptor {
    pub capacity: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredLinuxNode {
    pub node_id: [u8; 16],
    pub launch_generation: u64,
    pub descriptor: LinuxNodeDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeRegistryError {
    #[error("local node identity is unavailable or corrupt")]
    IdentityCorrupt,
    #[error("local node epoch is stale")]
    StaleEpoch,
    #[error("node descriptor is invalid or conflicts with registration")]
    InvalidDescriptor,
    #[error("node registry storage is unavailable or corrupt")]
    Storage,
}

/// Register the current local daemon epoch; same-epoch capability changes fail closed.
pub fn register_local_linux_node(
    connection: &Connection,
    node_id: [u8; 16],
    launch_generation: u64,
    descriptor: LinuxNodeDescriptor,
    ttl_seconds: u32,
) -> Result<RegisteredLinuxNode, NodeRegistryError> {
    validate_descriptor(descriptor, ttl_seconds)?;
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|_| NodeRegistryError::Storage)?;
    validate_current_epoch(&transaction, &node_id, launch_generation)?;
    let now = database_now_ms(&transaction)?;
    let existing = read_registration(&transaction, &node_id)?;
    if let Some(registration) = existing {
        validate_registration(&registration, now)?;
        let (stored_generation, _, _, _, _, capacity, _, expiry) = registration;
        if stored_generation <= 0 || stored_generation as u64 > launch_generation {
            return Err(NodeRegistryError::Storage);
        }
        if stored_generation as u64 == launch_generation && capacity != descriptor.capacity as i64 {
            return Err(NodeRegistryError::InvalidDescriptor);
        }
        if stored_generation as u64 == launch_generation && expiry <= now {
            return Err(NodeRegistryError::StaleEpoch);
        }
    }
    transaction
        .execute(
            "INSERT INTO execution_nodes (node_id,launch_generation,descriptor_version,platform,executor_protocol,workspace_backend,capacity,heartbeat_at_ms,expires_at_ms)
             VALUES (?1,?2,1,'linux','runne-taskrun-v1','git-worktree-v1',?3,?4,?5)
             ON CONFLICT(node_id) DO UPDATE SET launch_generation=excluded.launch_generation,descriptor_version=1,platform='linux',executor_protocol='runne-taskrun-v1',workspace_backend='git-worktree-v1',capacity=excluded.capacity,heartbeat_at_ms=excluded.heartbeat_at_ms,expires_at_ms=excluded.expires_at_ms",
            rusqlite::params![node_id.as_slice(), launch_generation, descriptor.capacity, now, now + i64::from(ttl_seconds) * 1000],
        )
        .map_err(|_| NodeRegistryError::Storage)?;
    transaction
        .commit()
        .map_err(|_| NodeRegistryError::Storage)?;
    Ok(RegisteredLinuxNode {
        node_id,
        launch_generation,
        descriptor,
    })
}

pub fn heartbeat_local_linux_node(
    connection: &Connection,
    node_id: [u8; 16],
    launch_generation: u64,
    ttl_seconds: u32,
) -> Result<(), NodeRegistryError> {
    validate_descriptor(LinuxNodeDescriptor { capacity: 1 }, ttl_seconds)?;
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|_| NodeRegistryError::Storage)?;
    validate_current_epoch(&transaction, &node_id, launch_generation)?;
    let now = database_now_ms(&transaction)?;
    let existing = read_registration(&transaction, &node_id)?;
    let Some(registration) = existing else {
        return Err(NodeRegistryError::StaleEpoch);
    };
    validate_registration(&registration, now)?;
    let (stored_generation, _, _, _, _, _, _, expiry) = registration;
    if stored_generation <= 0 {
        return Err(NodeRegistryError::Storage);
    }
    if stored_generation as u64 != launch_generation {
        return Err(NodeRegistryError::StaleEpoch);
    }
    if expiry <= now {
        return Err(NodeRegistryError::StaleEpoch);
    }
    let changed = transaction
        .execute(
            "UPDATE execution_nodes SET heartbeat_at_ms=?3,expires_at_ms=?4 WHERE node_id=?1 AND launch_generation=?2",
            rusqlite::params![node_id.as_slice(), launch_generation, now, now + i64::from(ttl_seconds) * 1000],
        )
        .map_err(|_| NodeRegistryError::Storage)?;
    if changed != 1 {
        return Err(NodeRegistryError::StaleEpoch);
    }
    transaction.commit().map_err(|_| NodeRegistryError::Storage)
}

pub fn eligible_local_linux_node(
    connection: &Connection,
) -> Result<Option<RegisteredLinuxNode>, NodeRegistryError> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
        .map_err(|_| NodeRegistryError::Storage)?;
    let identity = transaction
        .query_row(
            "SELECT authority_id FROM _authority WHERE id=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| NodeRegistryError::Storage)?
        .ok_or(NodeRegistryError::IdentityCorrupt)?;
    let node_id: [u8; 16] = identity
        .try_into()
        .map_err(|_| NodeRegistryError::IdentityCorrupt)?;
    if node_id == [0; 16] {
        return Err(NodeRegistryError::IdentityCorrupt);
    }
    let generation = current_generation(&transaction)?;
    let now = database_now_ms(&transaction)?;
    let row = read_registration(&transaction, &node_id)?;
    let result = row
        .map(|registration| {
            validate_registration(&registration, now)?;
            let (stored_generation, _, _, _, _, capacity, _, expiry) = registration;
            if stored_generation <= 0 || stored_generation as u64 > generation {
                return Err(NodeRegistryError::Storage);
            }
            if stored_generation as u64 != generation {
                return Ok(None);
            }
            if expiry <= now {
                return Ok(None);
            }
            Ok(Some(RegisteredLinuxNode {
                node_id,
                launch_generation: generation,
                descriptor: LinuxNodeDescriptor {
                    capacity: capacity as u32,
                },
            }))
        })
        .transpose()?
        .flatten();
    transaction
        .commit()
        .map_err(|_| NodeRegistryError::Storage)?;
    Ok(result)
}

fn validate_registration(
    registration: &PersistedNodeRegistration,
    now: i64,
) -> Result<(), NodeRegistryError> {
    let (_, version, platform, protocol, workspace, capacity, heartbeat, expiry) = registration;
    if *version != 1
        || platform != "linux"
        || protocol != "runne-taskrun-v1"
        || workspace != "git-worktree-v1"
        || *capacity <= 0
        || u32::try_from(*capacity).is_err()
        || *heartbeat <= 0
        || *heartbeat > now
        || *expiry <= *heartbeat
        || *expiry - *heartbeat > MAX_NODE_TTL_MS
    {
        return Err(NodeRegistryError::Storage);
    }
    Ok(())
}

fn database_now_ms(connection: &Connection) -> Result<i64, NodeRegistryError> {
    connection
        .query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| NodeRegistryError::Storage)
}

fn read_registration(
    connection: &Connection,
    node_id: &[u8; 16],
) -> Result<Option<PersistedNodeRegistration>, NodeRegistryError> {
    connection.query_row(
        "SELECT launch_generation,descriptor_version,platform,executor_protocol,workspace_backend,capacity,heartbeat_at_ms,expires_at_ms FROM execution_nodes WHERE node_id=?1",
        [node_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
    ).optional().map_err(|_| NodeRegistryError::Storage)
}

fn validate_current_epoch(
    connection: &Connection,
    node_id: &[u8; 16],
    generation: u64,
) -> Result<(), NodeRegistryError> {
    let identity = connection
        .query_row(
            "SELECT authority_id FROM _authority WHERE id=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| NodeRegistryError::Storage)?
        .ok_or(NodeRegistryError::IdentityCorrupt)?;
    if identity.as_slice() != node_id {
        return Err(NodeRegistryError::StaleEpoch);
    }
    if *node_id == [0; 16] {
        return Err(NodeRegistryError::IdentityCorrupt);
    }
    if current_generation(connection)? != generation {
        return Err(NodeRegistryError::StaleEpoch);
    }
    Ok(())
}

fn current_generation(connection: &Connection) -> Result<u64, NodeRegistryError> {
    let value: String = connection
        .query_row(
            "SELECT value FROM _daemon_info WHERE key='launch_generation'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| NodeRegistryError::Storage)?
        .ok_or(NodeRegistryError::IdentityCorrupt)?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| NodeRegistryError::IdentityCorrupt)?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(NodeRegistryError::IdentityCorrupt);
    }
    Ok(parsed)
}

fn validate_descriptor(
    descriptor: LinuxNodeDescriptor,
    ttl_seconds: u32,
) -> Result<(), NodeRegistryError> {
    if descriptor.capacity == 0 || ttl_seconds == 0 || ttl_seconds > 300 {
        return Err(NodeRegistryError::InvalidDescriptor);
    }
    Ok(())
}

#[cfg(test)]
#[path = "execution_node/tests.rs"]
mod tests;

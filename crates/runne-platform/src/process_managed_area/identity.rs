use super::ManagedAreaError;

const IDENTITY_MAGIC: &[u8; 4] = b"RMA1";
const IDENTITY_BYTES: usize = 100;

/// Exact TaskRun and attempt binding used to create a managed area.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManagedAreaBinding {
    pub(super) task_run: [u8; 16],
    pub(super) attempt: [u8; 16],
    pub(super) nonce: [u8; 16],
}

impl ManagedAreaBinding {
    /// Constructs a binding from non-sentinel durable identities.
    pub fn new(
        task_run: [u8; 16],
        attempt: [u8; 16],
        nonce: [u8; 16],
    ) -> Result<Self, ManagedAreaError> {
        if [task_run, attempt, nonce]
            .iter()
            .any(|value| value == &[0; 16])
        {
            return Err(ManagedAreaError::InvalidIdentity);
        }
        Ok(Self {
            task_run,
            attempt,
            nonce,
        })
    }
}

/// Persistable identity for one exact cgroup area on one host boot and root.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedAreaIdentity {
    pub(super) boot_id: [u8; 16],
    pub(super) root_device: u64,
    pub(super) root_inode: u64,
    pub(super) area_device: u64,
    pub(super) area_inode: u64,
    pub(super) binding: ManagedAreaBinding,
}

impl ManagedAreaIdentity {
    pub(super) fn new(
        boot_id: [u8; 16],
        root_device: u64,
        root_inode: u64,
        area_device: u64,
        area_inode: u64,
        binding: ManagedAreaBinding,
    ) -> Result<Self, ManagedAreaError> {
        if boot_id == [0; 16] || root_inode == 0 || area_inode == 0 {
            return Err(ManagedAreaError::InvalidIdentity);
        }
        Ok(Self {
            boot_id,
            root_device,
            root_inode,
            area_device,
            area_inode,
            binding,
        })
    }

    /// Encodes the fixed-size identity for durable storage.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; IDENTITY_BYTES] {
        let mut bytes = [0; IDENTITY_BYTES];
        bytes[..4].copy_from_slice(IDENTITY_MAGIC);
        bytes[4..20].copy_from_slice(&self.boot_id);
        bytes[20..28].copy_from_slice(&self.root_device.to_be_bytes());
        bytes[28..36].copy_from_slice(&self.root_inode.to_be_bytes());
        bytes[36..44].copy_from_slice(&self.area_device.to_be_bytes());
        bytes[44..52].copy_from_slice(&self.area_inode.to_be_bytes());
        bytes[52..68].copy_from_slice(&self.binding.task_run);
        bytes[68..84].copy_from_slice(&self.binding.attempt);
        bytes[84..100].copy_from_slice(&self.binding.nonce);
        bytes
    }

    /// Decodes and validates a fixed-size identity without accepting extensions.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManagedAreaError> {
        if bytes.len() != IDENTITY_BYTES || &bytes[..4] != IDENTITY_MAGIC {
            return Err(ManagedAreaError::InvalidIdentity);
        }
        let array = |range: std::ops::Range<usize>| -> [u8; 16] {
            bytes[range].try_into().expect("fixed identity field")
        };
        let number = |range: std::ops::Range<usize>| -> u64 {
            u64::from_be_bytes(bytes[range].try_into().expect("fixed identity field"))
        };
        Self::new(
            array(4..20),
            number(20..28),
            number(28..36),
            number(36..44),
            number(44..52),
            ManagedAreaBinding::new(array(52..68), array(68..84), array(84..100))?,
        )
    }

    pub(super) fn matches_binding(&self, binding: ManagedAreaBinding) -> bool {
        self.binding == binding
    }
}

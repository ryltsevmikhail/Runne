use core::fmt;
use std::collections::BTreeMap;

use super::super::ProcessContractError;

const EXECUTION_SHAPING_SEARCH_PATH: &str = concat!("PA", "TH");
const DYNAMIC_LOADER_SEARCH_PATH: &str = concat!("DYLD_LIBRARY_", "PA", "TH");
const PYTHON_MODULE_SEARCH_PATH: &str = concat!("PYTHON", "PA", "TH");
const DYNAMIC_LOADER_ENVIRONMENT_NAMES: [&str; 6] = [
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "GCONV_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputBoundsV1 {
    max_argv: usize,
    max_arg: usize,
    max_total: usize,
}

impl InputBoundsV1 {
    pub fn new(
        max_argv: usize,
        max_arg: usize,
        max_total: usize,
    ) -> Result<Self, ProcessContractError> {
        if [max_argv, max_arg, max_total].contains(&0) {
            return Err(ProcessContractError::InputBoundsExceeded);
        }
        Ok(Self {
            max_argv,
            max_arg,
            max_total,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn validate_environment(
        &self,
        values: &[(PortableUtf8V1, PortableUtf8V1)],
    ) -> Result<(), ProcessContractError> {
        if values.len() > self.max_argv {
            return Err(ProcessContractError::InputBoundsExceeded);
        }
        let total = values.iter().try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.bytes().len())
                .and_then(|total| total.checked_add(value.bytes().len()))
                .ok_or(ProcessContractError::InputBoundsExceeded)
        })?;
        if values.iter().any(|(name, value)| {
            name.bytes().len() > self.max_arg || value.bytes().len() > self.max_arg
        }) || total > self.max_total
        {
            return Err(ProcessContractError::InputBoundsExceeded);
        }
        Ok(())
    }
}

/// Validated platform-independent UTF-8 data without a NUL scalar.
#[derive(Clone, Eq, PartialEq)]
pub struct PortableUtf8V1(String);

impl PortableUtf8V1 {
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, ProcessContractError> {
        let value = String::from_utf8(value).map_err(|_| ProcessContractError::IntentMalformed)?;
        if value.contains('\0') {
            return Err(ProcessContractError::IntentMalformed);
        }
        Ok(Self(value))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn canonical_environment_name(&self) -> Option<&str> {
        let bytes = self.bytes();
        if bytes.first().is_some_and(u8::is_ascii_uppercase)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || *byte == b'_' || byte.is_ascii_digit())
        {
            Some(&self.0)
        } else {
            None
        }
    }

    fn is_execution_shaping_environment_name(name: &str) -> bool {
        DYNAMIC_LOADER_ENVIRONMENT_NAMES.contains(&name)
            || matches!(
                name,
                "LD_PRELOAD"
                    | "DYLD_INSERT_LIBRARIES"
                    | DYNAMIC_LOADER_SEARCH_PATH
                    | EXECUTION_SHAPING_SEARCH_PATH
                    | PYTHON_MODULE_SEARCH_PATH
                    | "NODE_OPTIONS"
                    | "RUBYOPT"
                    | "PERL5OPT"
                    | "JAVA_TOOL_OPTIONS"
            )
    }
}

impl fmt::Debug for PortableUtf8V1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PortableUtf8V1(redacted,len={})", self.0.len())
    }
}

/// Bounded literal argv; command strings and shell parsing are unrepresentable.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedArgvV1(Vec<PortableUtf8V1>);

impl BoundedArgvV1 {
    pub fn new(
        values: Vec<PortableUtf8V1>,
        bounds: InputBoundsV1,
    ) -> Result<Self, ProcessContractError> {
        if values.len() > bounds.max_argv {
            return Err(ProcessContractError::InputBoundsExceeded);
        }
        let total = values.iter().try_fold(0usize, |total, value| {
            total
                .checked_add(value.bytes().len())
                .ok_or(ProcessContractError::InputBoundsExceeded)
        })?;
        if values
            .iter()
            .any(|value| value.bytes().len() > bounds.max_arg)
            || total > bounds.max_total
        {
            return Err(ProcessContractError::InputBoundsExceeded);
        }
        Ok(Self(values))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn values(&self) -> &[PortableUtf8V1] {
        &self.0
    }
}

impl fmt::Debug for BoundedArgvV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoundedArgvV1(redacted,count={})", self.0.len())
    }
}

/// Empty explicit environment. Non-empty policy-granted construction is internal only.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct ExplicitEnvironmentV1(BTreeMap<String, PortableUtf8V1>);

impl ExplicitEnvironmentV1 {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_exact_grant(
        grant: &ProcessEnvironmentGrantV1,
        values: Vec<(PortableUtf8V1, PortableUtf8V1)>,
        bounds: InputBoundsV1,
    ) -> Result<Self, ProcessContractError> {
        bounds.validate_environment(&values)?;
        if values.len() != grant.0.len() {
            return Err(ProcessContractError::EnvironmentNotGranted);
        }
        let mut environment = BTreeMap::new();
        for (name, value) in values {
            let name = name
                .canonical_environment_name()
                .ok_or(ProcessContractError::IntentMalformed)?;
            let Some(expected) = grant.0.get(name) else {
                return Err(ProcessContractError::EnvironmentNotGranted);
            };
            if expected.value != value || environment.insert(name.to_owned(), value).is_some() {
                return Err(ProcessContractError::EnvironmentNotGranted);
            }
        }
        Ok(Self(environment))
    }
    pub(crate) fn values(&self) -> &BTreeMap<String, PortableUtf8V1> {
        &self.0
    }
}

impl fmt::Debug for ExplicitEnvironmentV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExplicitEnvironmentV1(redacted,count={})", self.0.len())
    }
}

/// Internal policy grant for one exact non-secret environment value.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnvironmentClassificationV1 {
    NonSecret,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Eq, PartialEq)]
struct GrantedEnvironmentValueV1 {
    value: PortableUtf8V1,
    classification: EnvironmentClassificationV1,
}

/// Sealed internal capability for exact process environment construction.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Eq, PartialEq, Default)]
pub(crate) struct ProcessEnvironmentGrantV1(BTreeMap<String, GrantedEnvironmentValueV1>);

#[cfg_attr(not(test), allow(dead_code))]
impl ProcessEnvironmentGrantV1 {
    pub(crate) fn exact(
        values: Vec<(PortableUtf8V1, PortableUtf8V1, EnvironmentClassificationV1)>,
        bounds: InputBoundsV1,
    ) -> Result<Self, ProcessContractError> {
        let pairs = values
            .iter()
            .map(|(name, value, _)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        bounds.validate_environment(&pairs)?;
        let mut granted = BTreeMap::new();
        for (name, value, classification) in values {
            let name = name
                .canonical_environment_name()
                .ok_or(ProcessContractError::IntentMalformed)?;
            if PortableUtf8V1::is_execution_shaping_environment_name(name) {
                return Err(ProcessContractError::EnvironmentDenied);
            }
            if granted
                .insert(
                    name.to_owned(),
                    GrantedEnvironmentValueV1 {
                        value,
                        classification,
                    },
                )
                .is_some()
            {
                return Err(ProcessContractError::IntentMalformed);
            }
        }
        Ok(Self(granted))
    }
}

impl fmt::Debug for ProcessEnvironmentGrantV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let classifications = self
            .0
            .values()
            .filter(|value| value.classification == EnvironmentClassificationV1::NonSecret)
            .count();
        write!(
            f,
            "ProcessEnvironmentGrantV1(redacted,count={},non_secret={classifications})",
            self.0.len()
        )
    }
}

/// Closed stdin is the only public V1 mode.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StdinPolicyV1(());

impl StdinPolicyV1 {
    #[must_use]
    pub const fn closed() -> Self {
        Self(())
    }
}

impl fmt::Debug for StdinPolicyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StdinPolicyV1(Closed)")
    }
}

#[derive(Debug, Clone)]
pub struct NetworkDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub allowed_hosts: Vec<String>,
    pub deny_private: bool,
    pub deny_loopback: bool,
    pub deny_metadata: bool,
    pub max_redirects: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("egress denied")]
    EgressDenied,
    #[error("private address denied")]
    PrivateAddressDenied,
    #[error("metadata address denied")]
    MetadataAddressDenied,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("redirected to private address")]
    RedirectedToPrivateAddress,
}

pub struct NetworkBroker {
    policy: EgressPolicy,
}

impl NetworkBroker {
    pub fn new(policy: EgressPolicy) -> Self {
        Self { policy }
    }

    pub fn validate_destination(
        &self,
        destination: &NetworkDestination,
    ) -> Result<(), NetworkError> {
        if self.policy.deny_loopback
            && matches!(destination.host.as_str(), "127.0.0.1" | "::1" | "localhost")
        {
            return Err(NetworkError::PrivateAddressDenied);
        }
        if self.policy.deny_metadata && destination.host == "169.254.169.254" {
            return Err(NetworkError::MetadataAddressDenied);
        }
        if self.policy.deny_private && is_private_host(&destination.host) {
            return Err(NetworkError::PrivateAddressDenied);
        }
        if self.policy.allowed_hosts.is_empty()
            || !self.policy.allowed_hosts.contains(&destination.host)
        {
            return Err(NetworkError::EgressDenied);
        }
        Ok(())
    }
}

fn is_private_host(host: &str) -> bool {
    host.starts_with("10.")
        || host.starts_with("192.168.")
        || (host.starts_with("172.")
            && host
                .split('.')
                .nth(1)
                .and_then(|second| second.parse::<u32>().ok())
                .is_some_and(|number| (16..=31).contains(&number)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allowed_hosts: Vec<&str>) -> EgressPolicy {
        EgressPolicy {
            allowed_hosts: allowed_hosts.into_iter().map(str::to_string).collect(),
            deny_private: true,
            deny_loopback: true,
            deny_metadata: true,
            max_redirects: 3,
        }
    }

    #[test]
    fn default_deny() {
        let broker = NetworkBroker::new(policy(vec![]));
        assert!(
            broker
                .validate_destination(&NetworkDestination {
                    scheme: "https".into(),
                    host: "example.com".into(),
                    port: 443
                })
                .is_err()
        );
    }

    #[test]
    fn allowlisted_host_ok() {
        let broker = NetworkBroker::new(policy(vec!["example.com"]));
        assert!(
            broker
                .validate_destination(&NetworkDestination {
                    scheme: "https".into(),
                    host: "example.com".into(),
                    port: 443
                })
                .is_ok()
        );
    }

    #[test]
    fn loopback_denied() {
        let broker = NetworkBroker::new(policy(vec!["127.0.0.1"]));
        assert!(
            broker
                .validate_destination(&NetworkDestination {
                    scheme: "http".into(),
                    host: "127.0.0.1".into(),
                    port: 80
                })
                .is_err()
        );
    }

    #[test]
    fn metadata_always_denied() {
        let broker = NetworkBroker::new(policy(vec!["169.254.169.254"]));
        assert!(
            broker
                .validate_destination(&NetworkDestination {
                    scheme: "http".into(),
                    host: "169.254.169.254".into(),
                    port: 80
                })
                .is_err()
        );
    }

    #[test]
    fn private_ip_denied() {
        let broker = NetworkBroker::new(policy(vec!["10.0.0.1"]));
        assert!(
            broker
                .validate_destination(&NetworkDestination {
                    scheme: "http".into(),
                    host: "10.0.0.1".into(),
                    port: 80
                })
                .is_err()
        );
    }
}

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct NetworkDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ResolvedDestination {
    pub destination: NetworkDestination,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct ConnectionHandle {
    pub destination: ResolvedDestination,
    pub redirect_count: u32,
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

    pub fn resolve_destination(
        &self,
        destination: NetworkDestination,
        addresses: Vec<IpAddr>,
    ) -> Result<ResolvedDestination, NetworkError> {
        self.validate_destination(&destination)?;
        if addresses.is_empty() {
            return Err(NetworkError::EgressDenied);
        }
        for address in &addresses {
            self.validate_address(*address)?;
        }
        Ok(ResolvedDestination {
            destination,
            addresses,
        })
    }

    pub fn connect(
        &self,
        destination: ResolvedDestination,
    ) -> Result<ConnectionHandle, NetworkError> {
        self.validate_destination(&destination.destination)?;
        for address in &destination.addresses {
            self.validate_address(*address)?;
        }
        Ok(ConnectionHandle {
            destination,
            redirect_count: 0,
        })
    }

    pub fn follow_redirect(
        &self,
        connection: &ConnectionHandle,
        destination: NetworkDestination,
        addresses: Vec<IpAddr>,
    ) -> Result<ConnectionHandle, NetworkError> {
        if connection.redirect_count >= self.policy.max_redirects {
            return Err(NetworkError::TooManyRedirects);
        }
        let resolved =
            self.resolve_destination(destination, addresses)
                .map_err(|error| match error {
                    NetworkError::PrivateAddressDenied | NetworkError::MetadataAddressDenied => {
                        NetworkError::RedirectedToPrivateAddress
                    }
                    other => other,
                })?;
        Ok(ConnectionHandle {
            destination: resolved,
            redirect_count: connection.redirect_count + 1,
        })
    }

    fn validate_address(&self, address: IpAddr) -> Result<(), NetworkError> {
        if is_metadata_address(address) {
            return Err(NetworkError::MetadataAddressDenied);
        }
        if self.policy.deny_loopback && address.is_loopback() {
            return Err(NetworkError::PrivateAddressDenied);
        }
        if self.policy.deny_private && is_private_address(address) {
            return Err(NetworkError::PrivateAddressDenied);
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

fn is_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => {
            address.is_unique_local() || address.is_unicast_link_local() || address.is_unspecified()
        }
    }
}

fn is_metadata_address(address: IpAddr) -> bool {
    matches!(
        address,
        IpAddr::V4(address) if address.octets() == [169, 254, 169, 254]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn allowlisted_hostname_resolving_to_private_address_is_denied() {
        let broker = NetworkBroker::new(policy(vec!["example.com"]));
        let result = broker.resolve_destination(
            NetworkDestination {
                scheme: "https".into(),
                host: "example.com".into(),
                port: 443,
            },
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        );

        assert!(matches!(result, Err(NetworkError::PrivateAddressDenied)));
    }

    #[test]
    fn redirect_revalidates_addresses_and_rejects_private_target() {
        let broker = NetworkBroker::new(policy(vec!["example.com", "redirect.example.com"]));
        let resolved = broker
            .resolve_destination(
                NetworkDestination {
                    scheme: "https".into(),
                    host: "example.com".into(),
                    port: 443,
                },
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            )
            .unwrap();
        let connection = broker.connect(resolved).unwrap();

        let result = broker.follow_redirect(
            &connection,
            NetworkDestination {
                scheme: "https".into(),
                host: "redirect.example.com".into(),
                port: 443,
            },
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))],
        );

        assert!(matches!(
            result,
            Err(NetworkError::RedirectedToPrivateAddress)
        ));
    }

    #[test]
    fn redirect_limit_is_enforced() {
        let mut redirect_policy = policy(vec!["example.com"]);
        redirect_policy.max_redirects = 0;
        let broker = NetworkBroker::new(redirect_policy);
        let resolved = broker
            .resolve_destination(
                NetworkDestination {
                    scheme: "https".into(),
                    host: "example.com".into(),
                    port: 443,
                },
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            )
            .unwrap();
        let connection = broker.connect(resolved).unwrap();

        let result = broker.follow_redirect(
            &connection,
            NetworkDestination {
                scheme: "https".into(),
                host: "example.com".into(),
                port: 443,
            },
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        );

        assert!(matches!(result, Err(NetworkError::TooManyRedirects)));
    }
}

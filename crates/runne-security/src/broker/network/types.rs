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

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

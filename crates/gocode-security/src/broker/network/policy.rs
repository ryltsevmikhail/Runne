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

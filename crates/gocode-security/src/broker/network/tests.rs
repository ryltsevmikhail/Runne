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

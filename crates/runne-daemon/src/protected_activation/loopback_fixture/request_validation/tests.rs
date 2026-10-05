use super::{FixtureRequestKind, request_length, request_length_for};

fn valid_headers() -> String {
    concat!(
        "host: api.openai.com\r\n",
        "content-type: application/json\r\n",
        "content-length: 0\r\n",
        "authorization: Bearer x\r\n",
        "x-client-request-id: gocode-provider-c436f15d42859a67270a2f39ff1c8508\r\n",
        "accept: */*\r\n",
    )
    .to_owned()
}

fn request(headers: &str) -> String {
    format!("POST /v1/responses HTTP/1.1\r\n{headers}\r\n")
}

#[test]
fn rejects_missing_duplicate_unknown_and_transfer_headers() {
    let headers = valid_headers();
    for invalid in [
        headers.replace("accept: */*\r\n", ""),
        format!("{headers}host: api.openai.com\r\n"),
        format!("{headers}accept-encoding: gzip\r\n"),
        format!("{headers}transfer-encoding: chunked\r\n"),
    ] {
        assert!(request_length(request(&invalid).as_bytes()).is_err());
    }
}

#[test]
fn accepts_exact_six_required_headers_with_exact_accept_value() {
    assert_eq!(request_length(request(&valid_headers()).as_bytes()), Ok(0));
}

#[test]
fn accepts_the_pre_rename_provider_idempotency_vector() {
    let headers = concat!(
        "host: api.openai.com\r\n",
        "content-type: application/json\r\n",
        "content-length: 0\r\n",
        "authorization: Bearer x\r\n",
        "x-client-request-id: gocode-provider-c436f15d42859a67270a2f39ff1c8508\r\n",
        "accept: */*\r\n",
    );
    assert_eq!(request_length(request(headers).as_bytes()), Ok(0));
}

#[test]
fn service_point_of_use_accepts_only_canonical_dynamic_request_ids() {
    let headers = valid_headers();
    let dynamic = headers.replace(
        super::EXPECTED_REQUEST_ID,
        "gocode-provider-0123456789abcdef0123456789abcdef",
    );
    assert_eq!(
        request_length_for(
            request(&dynamic).as_bytes(),
            FixtureRequestKind::ServicePointOfUse,
        ),
        Ok(0)
    );
    for invalid in [
        dynamic.replace("gocode-provider-", "runne-provider-"),
        dynamic.replace('f', "F"),
        dynamic.replace("0123456789abcdef", "0123456789abcde"),
    ] {
        assert!(
            request_length_for(
                request(&invalid).as_bytes(),
                FixtureRequestKind::ServicePointOfUse,
            )
            .is_err()
        );
    }
}

#[test]
fn d2_fixture_accepts_only_round_bound_request_ids() {
    let headers = valid_headers();
    let dynamic = headers.replace(
        super::EXPECTED_REQUEST_ID,
        "gocode-d2-round-0123456789abcdef0123456789abcdef",
    );
    assert_eq!(
        request_length_for(
            request(&dynamic).as_bytes(),
            FixtureRequestKind::D2ToolProposal,
        ),
        Ok(0)
    );
    let wrong_profile_prefix = dynamic.replace("gocode-d2-round-", "gocode-provider-");
    assert!(
        request_length_for(
            request(&wrong_profile_prefix).as_bytes(),
            FixtureRequestKind::D2ToolProposal,
        )
        .is_err()
    );
    let d2_id_on_text_route = dynamic.replace("gocode-d2-round-", "gocode-provider-");
    assert!(
        request_length_for(
            request(&d2_id_on_text_route).as_bytes(),
            FixtureRequestKind::ServicePointOfUse,
        )
        .is_ok()
    );
}

#[test]
fn rejects_non_exact_accept_value() {
    let headers = valid_headers().replace("accept: */*", "accept: application/json");
    assert!(request_length(request(&headers).as_bytes()).is_err());
}

#[test]
fn rejects_non_exact_host_content_type_and_request_id() {
    let headers = valid_headers();
    for invalid in [
        headers.replace("host: api.openai.com", "host: api.example.com"),
        headers.replace("content-type: application/json", "content-type: text/plain"),
        headers.replace(
            "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
            "other-provider-0123456789abcdef0123456789abcdef",
        ),
        headers.replace(
            "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
            "runne-provider-cb1a6843c5c332cda4a0f78cc9d606ce",
        ),
        headers.replace(
            "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
            "gocode-provider-0123456789abcdef0123456789abcde",
        ),
        headers.replace(
            "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
            "gocode-provider-0123456789abcdef0123456789abcdeF",
        ),
    ] {
        assert!(request_length(request(&invalid).as_bytes()).is_err());
    }
}

#[test]
fn rejects_invalid_header_separator_and_ows() {
    let headers = valid_headers();
    for invalid in [
        headers.replace("host: api.openai.com", "host:api.openai.com"),
        headers.replace("host: api.openai.com", "host:  api.openai.com"),
        headers.replace("host: api.openai.com", "host:\tapi.openai.com"),
        headers.replace("host: api.openai.com", " host: api.openai.com"),
        headers.replace("host: api.openai.com", "host: api.openai.com "),
    ] {
        assert!(request_length(request(&invalid).as_bytes()).is_err());
    }
}

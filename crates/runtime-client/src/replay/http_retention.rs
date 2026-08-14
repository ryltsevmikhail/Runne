use super::CONTENT_TYPE;
use super::validation::parse_uuid_v7;

pub(super) fn has_exact_retention_content_type(response: &reqwest::Response) -> bool {
    let values: Vec<_> = response.headers().get_all(CONTENT_TYPE).iter().collect();
    values.len() == 1 && values[0].to_str().ok() == Some("application/json")
}

pub(super) fn has_exact_no_store(response: &reqwest::Response) -> bool {
    let values: Vec<_> = response.headers().get_all("cache-control").iter().collect();
    values.len() == 1 && values[0].to_str().ok() == Some("no-store")
}

pub(super) fn retention_request_id(response: &reqwest::Response) -> Option<String> {
    let values: Vec<_> = response.headers().get_all("x-request-id").iter().collect();
    (values.len() == 1)
        .then(|| values[0].to_str().ok())
        .flatten()
        .filter(|value| parse_uuid_v7(value).is_ok())
        .map(str::to_owned)
}

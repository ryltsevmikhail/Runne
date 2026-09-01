#![cfg(test)]

#[path = "writer_endpoint_handoff_tests/acceptance.rs"]
mod acceptance;
#[path = "writer_endpoint_handoff_tests/deadline.rs"]
mod deadline;
#[path = "writer_endpoint_handoff_tests/raw_parser.rs"]
mod raw_parser;
#[path = "writer_endpoint_handoff_tests/rejections.rs"]
mod rejections;
#[path = "writer_endpoint_handoff_tests/support.rs"]
mod support;

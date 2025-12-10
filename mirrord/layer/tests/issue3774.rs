#![feature(assert_matches)]
#![warn(clippy::indexing_slicing)]

use std::{path::Path, time::Duration};

use mirrord_protocol::{
    ClientMessage,
    tcp::{Filter, HttpFilter, LayerTcpSteal, StealType},
};
use rstest::rstest;

mod common;

pub use common::*;

/// Test that wildcard ports configuration (`ports: ["*"]`) sends `FilteredHttpEx`
/// for non-standard ports.
///
/// Issue #3774: When `http_filter` is defined without specifying `ports`, it defaults
/// to `[80, 8080]`, causing traffic on non-standard ports to be silently dropped.
/// The wildcard `["*"]` allows HTTP filtering to apply to ALL ports.
///
/// This test verifies that when `ports: ["*"]` is configured, the layer correctly
/// sends `StealType::FilteredHttpEx` for port 9999 (instead of `StealType::All`).
#[rstest]
#[tokio::test]
#[timeout(Duration::from_secs(60))]
async fn test_wildcard_port_subscription(dylib_path: &Path, config_dir: &Path) {
    let config_path = config_dir.join("http_filter_wildcard.json");

    // RustIssue2058 listens on port 9999 - a non-standard port that would normally
    // NOT be covered by the default http_filter ports [80, 8080]
    let application = Application::RustIssue2058;

    let (mut test_process, mut intproxy) = application
        .start_process_with_layer(dylib_path, vec![], Some(&config_path))
        .await;

    let message = intproxy.recv().await;

    // Verify we get FilteredHttpEx for port 9999 (not StealType::All)
    // This confirms the wildcard ["*"] is working correctly
    match message {
        ClientMessage::TcpSteal(LayerTcpSteal::PortSubscribe(StealType::FilteredHttpEx(
            port,
            HttpFilter::Header(filter),
        ))) => {
            assert_eq!(port, 9999, "Expected port 9999 for RustIssue2058 app");
            assert_eq!(filter, Filter::new("x-test: yes".into()).unwrap());
        }
        other => panic!("Expected FilteredHttpEx with header filter, got: {other:?}"),
    }

    test_process
        .child
        .kill()
        .await
        .expect("failed to kill the app");
}

/// Test that no warning appears when using wildcard ports for non-standard ports.
///
/// When using specific port filtering (e.g., `ports: [3000]`), the layer warns if
/// the application listens on a port not in the filtered list. With wildcard `["*"]`,
/// this warning should NOT appear since all ports are covered.
///
/// Contrast with `warn_ignored_unfiltered_port` test which expects the warning.
#[rstest]
#[tokio::test]
#[timeout(Duration::from_secs(20))]
async fn test_wildcard_no_warning_for_non_standard_port(dylib_path: &Path, config_dir: &Path) {
    let config_path = config_dir.join("http_filter_wildcard.json");

    // RustIssue2058 listens on port 9999
    let application = Application::RustIssue2058;

    let (mut test_process, _intproxy) = application
        .start_process_with_layer(dylib_path, vec![], Some(&config_path))
        .await;

    // Give the app time to start and potentially log warnings
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The warning "Port 9999 was not included in the filtered ports" should NOT appear
    // because wildcard ["*"] covers all ports
    test_process.assert_no_error_in_stderr().await;

    test_process
        .child
        .kill()
        .await
        .expect("failed to kill the app");
}

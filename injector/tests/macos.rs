#![cfg(target_os = "macos")]

mod macos_common;

#[test]
fn test_inject() {
    macos_common::test_inject()
}

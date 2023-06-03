use std::env::var;

// pls fix https://github.com/rust-lang/cargo/issues/9554 ...
fn main() {
    if var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        // Make shellcode segment executable
        println!("cargo:rustc-link-arg=-segprot");
        println!("cargo:rustc-link-arg=__SHELLCODE");
        println!("cargo:rustc-link-arg=rx");
        println!("cargo:rustc-link-arg=rx");

        if var("CARGO_CFG_TARGET_ARCH").unwrap() == "aarch64" {
            println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=12.0");
        } else {
            println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=10.13");
        }
    }
}

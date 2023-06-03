use std::env::var;

fn main() {
    if var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        // Make shellcode segment executable
        println!("cargo:rustc-link-arg=-segprot");
        println!("cargo:rustc-link-arg=__SHELLCODE");
        println!("cargo:rustc-link-arg=rx");
        println!("cargo:rustc-link-arg=rx");
    }
}

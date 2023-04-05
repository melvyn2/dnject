#![allow(dead_code)] // Some only exported

pub const STARTUP_MSG: &[u8; 16] = b"testbin started\n";

pub const INJECTED_MSG: &[u8; 19] = b"testlib injected !\n";
pub const EJECTED_MSG: &[u8; 18] = b"testlib ejected !\n";

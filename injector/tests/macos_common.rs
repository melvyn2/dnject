#![allow(dead_code)]
// Actual test code for macos
// `macos.rs` and `macos_hardened.rs` have the test-annotated functions, so that tests are ran
// sequentially and in different binaries

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::Once;

use libc::pid_t;

use apple_codesign::{CodeSignatureFlags, SettingsScope, SigningSettings, UnifiedSigner};

use injector::ProcHandle;

use mach_util::TempFile;

// Why include and write to disk? CLion's remote running (such as for i686 mojave VMs) doesn't seem to
// account for bindeps, so doesn't copy them into the guest environment. We do it ourselves
const TESTLIB: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_TESTLIB"));
const TESTBIN: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_TESTBIN"));

const ENT_XML_TARGET: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>"#;

const ENT_XML_TARGET_HARDENED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>"#;

static LOGGER: Once = Once::new();

fn logger_init() {
    LOGGER.call_once(|| {
        env_logger::Builder::new()
            .filter_module("injector::macos", log::LevelFilter::Trace)
            .is_test(true)
            .parse_default_env()
            .init()
    })
}

pub fn test_inject_hardened() {
    logger_init();

    // Create target signed with get-task-allow entitlement
    let bin = create_bin(TESTBIN, Some(ENT_XML_TARGET_HARDENED), true).unwrap();

    // Write lib
    let lib = create_bin(TESTLIB, None, false).unwrap();

    let mut proc = Command::new(bin.as_os_str());
    proc.stdout(Stdio::piped());
    proc.stderr(Stdio::inherit());
    let mut child = proc.spawn().unwrap();

    // Get handle by macos_portfetch
    let port = macos_portfetch::get_port_signed(child.id() as pid_t).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });
    let mut handle = ProcHandle::try_from(port).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });

    // Ensure child started properly
    let mut out = vec![0u8; testbin::STARTUP_MSG.len()];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(out.as_mut_slice())
        .unwrap();
    assert_eq!(&out, testbin::STARTUP_MSG);
    // Ensure child is still running
    assert_eq!(child.try_wait().unwrap(), None);

    // Inject (duh)
    handle.inject(&[lib.clone()]).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });

    // Kill child process (and ignore error if it already exited)
    let _ = child.kill();
}

pub fn test_inject() {
    logger_init();

    // Create target signed with get-task-allow entitlement
    let bin = create_bin(TESTBIN, Some(ENT_XML_TARGET), false).unwrap();
    let lib = create_bin(TESTLIB, None, false).unwrap();

    let mut proc = Command::new(bin.as_os_str());
    proc.stdout(Stdio::piped());
    proc.stderr(Stdio::inherit());
    let mut child = proc.spawn().unwrap();

    // Get handle by task_for_pid
    let mut handle = ProcHandle::try_from(child.id() as pid_t).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });

    // Ensure child started properly
    let startup_stdout = {
        let mut o = vec![0u8; testbin::STARTUP_MSG.len()];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(o.as_mut_slice())
            .unwrap();
        o
    };
    assert_eq!(&startup_stdout, testbin::STARTUP_MSG);
    // Ensure child is still running
    assert_eq!(child.try_wait().unwrap(), None);

    // Inject (duh)
    handle.inject(&[lib.clone()]).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });

    // Ensure injected library did its thing (wrote to stdout)
    let injected_stdout = {
        let mut o = vec![0u8; testbin::INJECTED_MSG.len()];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(o.as_mut_slice())
            .unwrap();
        o
    };
    assert_eq!(&injected_stdout, testbin::INJECTED_MSG);

    // Eject
    handle.eject(None).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });

    // Ensure injected library did its thing (wrote to stdout)
    let ejected_stdout = {
        let mut o = vec![0u8; testbin::EJECTED_MSG.len()];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(o.as_mut_slice())
            .unwrap();
        o
    };
    assert_eq!(&ejected_stdout, testbin::EJECTED_MSG);

    // Kill child process (and ignore error if it already exited)
    let _ = child.kill();
}

fn create_bin(
    bin: &[u8],
    ent: Option<&str>,
    hardened: bool,
) -> Result<TempFile, Box<dyn std::error::Error>> {
    let out_bin = TempFile::random("injtest", None);

    fs::write(out_bin.as_path(), bin)?;
    fs::set_permissions(out_bin.as_path(), fs::Permissions::from_mode(0o700))?;

    if let Some(ent_xml) = ent {
        let mut sign = SigningSettings::default();
        sign.set_entitlements_xml(SettingsScope::Main, ent_xml)?;
        if hardened {
            sign.add_code_signature_flags(SettingsScope::Main, CodeSignatureFlags::RUNTIME);
        }
        UnifiedSigner::new(sign).sign_macho(out_bin.as_path(), out_bin.as_path())?;
    }

    Ok(out_bin)
}

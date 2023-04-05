#![feature(io_error_more)]
#![cfg(target_os = "macos")]

use apple_codesign::{CodeSignatureFlags, SettingsScope, SigningSettings, UnifiedSigner};
use std::collections::hash_map::DefaultHasher;
use std::ffi::OsStr;
use std::fs;
use std::hash::Hasher;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Once;

use libc::pid_t;

use injector::ProcHandle;

// Why include and write to disk? CLion's remote running (for i686 mojave VMs) doesn't seem to
// account for bindeps, so doesn't copy them into the guest environment. We do it ourselves
const TESTLIB: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_TESTLIB"));
const TESTBIN: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_TESTBIN"));

const ENT_XML_INJECTOR: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.debugger</key>
    <true/>
</dict>
</plist>"#;

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
    <key>com.apple.security.cs.disable-library-validation</key>
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

// TODO make test binary signed with `com.apple.cs.security.debugger`
#[test]
#[ignore = "codesigning test binary not implemented"]
fn test_inject_hardened() {
    logger_init();

    // Create target signed with get-task-allow entitlement
    let bin = create_bin(TESTBIN, Some(ENT_XML_TARGET_HARDENED), true).unwrap();

    // Write lib
    let lib = create_bin(TESTLIB, None, false).unwrap();

    // For some reason clippy thinks that the borrow is unnecessary... it isn't
    #[allow(clippy::needless_borrow)]
    let mut proc = Command::new(&bin.0);
    proc.stdout(Stdio::piped());
    proc.stderr(Stdio::inherit());
    let mut child = proc.spawn().unwrap();

    // Get handle by task_for_pid
    let mut handle = ProcHandle::try_from(child.id() as pid_t).unwrap_or_else(|e| {
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
    handle.inject(&[lib.0.clone()]).unwrap_or_else(|e| {
        let _ = child.kill();
        Err(e).unwrap()
    });

    // Kill child process (and ignore error if it already exited)
    let _ = child.kill();
}

#[test]
fn test_inject() {
    logger_init();

    // Create target signed with get-task-allow entitlement
    let bin = create_bin(TESTBIN, Some(ENT_XML_TARGET), false).unwrap();
    let lib = create_bin(TESTLIB, None, false).unwrap();

    // For some reason clippy thinks that the borrow is unnecessary... it isn't
    #[allow(clippy::needless_borrow)]
    let mut proc = Command::new(&bin.0);
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
    handle.inject(&[lib.0.clone()]).unwrap_or_else(|e| {
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

    // Kill child process (and ignore error if it already exited)
    let _ = child.kill();
}

// Ensure temp re-signed files are deleted
struct TempFile(PathBuf);
impl Drop for TempFile {
    // Can't really do anything if the file isn't deletable, so ignore errors
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        fs::remove_file(&self.0);
    }
}

fn create_bin(
    bin: &[u8],
    ent: Option<&str>,
    hardened: bool,
) -> Result<TempFile, Box<dyn std::error::Error>> {
    let mut out_bin = PathBuf::from("/tmp");

    // Set ext to hash of inputs, to avoid collision with parallel tests
    let ext = {
        let mut ext_hasher = DefaultHasher::new();
        if let Some(e) = ent {
            ext_hasher.write(e.as_bytes());
        }
        ext_hasher.write_u8(hardened as u8);
        format!("injtest-{:x}", ext_hasher.finish())
    };

    out_bin.push(OsStr::new(ext.as_str()));

    fs::write(&out_bin, bin)?;
    fs::set_permissions(&out_bin, fs::Permissions::from_mode(0o700))?;

    if let Some(ent_xml) = ent {
        let mut sign = SigningSettings::default();
        sign.set_entitlements_xml(SettingsScope::Main, ent_xml)?;
        if hardened {
            sign.add_code_signature_flags(SettingsScope::Main, CodeSignatureFlags::RUNTIME);
        }
        UnifiedSigner::new(sign).sign_macho(&out_bin, &out_bin)?;
    }

    Ok(TempFile(out_bin))
}

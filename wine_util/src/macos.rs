use std::collections::HashMap;
use std::ffi::{CStr, OsStr};
use std::io::ErrorKind;
use std::mem::transmute;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use libc::{c_char, pid_t};

use mach_util::mapinfo::mappings_for_pid;

use sysinfo::{Pid, ProcessExt, System, SystemExt};

use crate::WineEnv;

fn find_wine_dir(pid: pid_t) -> Result<Option<PathBuf>, std::io::Error> {
    // SAFETY: transmute is safe because char should hopefully always be 8 bits and ASCII doesn't touch sign bit
    const PATH_PFX: &[c_char; 19] =
        unsafe { transmute::<&[u8; 19], &[c_char; 19]>(b"/private/tmp/.wine-") };
    for reg in mappings_for_pid(pid)? {
        if &reg.prp_vip.vip_path[0][..PATH_PFX.len()] == PATH_PFX {
            let cstr = unsafe { CStr::from_ptr(reg.prp_vip.vip_path[0].as_ptr()) };
            let path = Path::new(OsStr::from_bytes(cstr.to_bytes()));
            return Ok(path.parent().map(|p| p.to_path_buf()));
        }
    }
    Ok(None)
}

impl WineEnv {
    /// Return the windows executable and wine environment of the target pid,
    /// if it exists and is a valid wine process
    pub fn get(pid: pid_t, system: &System) -> Result<Option<WineEnv>, std::io::Error> {
        // For some reason, only the wineserver has environment variables we can access, so we need to find it instead
        // Get open mem-maps of target, search for /private/tmp/.wine-(UID)/server-*/*,
        // Get directory of that file,
        // Find wineserver with matching CWD
        // Use the env and path of that wineserver process to find WINEPREFIX and binary

        let proc = system.process(Pid::from(pid as usize)).ok_or_else(|| {
            std::io::Error::new(ErrorKind::NotFound, format!("pid {} not found", pid))
        })?;

        // Get wineserver directory of target
        let wineserver_cwd = match find_wine_dir(pid)? {
            Some(p) => p,
            None => return Ok(None),
        };

        let wineserver = system
            .processes()
            .iter()
            .find(|(_, proc)| proc.cwd() == wineserver_cwd)
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "no matching wineserver found for process",
                )
            })?
            .1;

        let wineloader = wineserver
            .environ()
            .iter()
            .find_map(|e| {
                if e.starts_with("WINELOADER=") {
                    Some(PathBuf::from(e.replacen("WINELOADER=", "", 1)))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "wine process missing WINELOADER environment variable",
                )
            })?;

        let wineprefix = wineserver.environ().iter().find_map(|e| {
            if e.starts_with("WINEPREFIX=") {
                Some(PathBuf::from(e.replacen("WINEPREFIX=", "", 1)))
            } else {
                None
            }
        });

        let wine_env = wineserver
            .environ()
            .iter()
            .filter_map(|e| {
                if e.starts_with("WINE") {
                    e.split_once('=')
                } else {
                    None
                }
            })
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<String, String>>();

        let exe = if proc.name().ends_with("preloader") {
            proc.cmd().get(1).map(|s| s.clone())
        } else {
            None
        };

        Ok(Some(WineEnv {
            exe,
            loader: wineloader,
            prefix: wineprefix,
            env: wine_env,
        }))
    }
}

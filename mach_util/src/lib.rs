#![feature(extern_types)]
#![feature(negative_impls)]

//! C-defs which aren't included in mach2, as well as helper classes

mod stubs;
pub use stubs::*;

pub mod error;

pub mod mach_portal;

use std::collections::hash_map::DefaultHasher;
use std::fmt::Display;
use std::hash::Hasher;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub fn get_pid_cpu_type(pid: libc::pid_t) -> Result<libc::cpu_type_t, std::io::Error> {
    // See https://github.com/objective-see/ProcessMonitor/blob/1a9c2e0c8044ad10676efad480f200f12060ed7a/Library/Source/Process.m#L252

    use crate::machine::{CPU_TYPE_ANY, CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    use crate::proc::P_TRANSLATED;
    use crate::sysctl::{kinfo_proc, CTL_MAXNAME};
    use libc::{c_int, c_uint, c_void, cpu_type_t, sysctl};
    use std::ffi::CStr;
    use std::mem::size_of;
    use std::ptr::{addr_of_mut, null_mut};

    let mut mib: [c_int; CTL_MAXNAME] = [0; CTL_MAXNAME];
    let mut mib_length = CTL_MAXNAME;
    let sysctl_str = CStr::from_bytes_with_nul(b"sysctl.proc_cputype\0")
        .unwrap()
        .as_ptr();
    unsafe {
        let res = libc::sysctlnametomib(sysctl_str, mib.as_mut_ptr(), addr_of_mut!(mib_length));
        if res != 0 {
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                "sysctlnametomib proc_cputype failed",
            ));
        };
    }
    // mib_length now contains the number of written elements, not total elements
    // Write target pid to the next unwritten element
    mib[mib_length] = pid;
    mib_length += 1;

    let mut cpu_type: cpu_type_t = CPU_TYPE_ANY;
    let mut cpu_type_size = size_of::<cpu_type_t>();

    unsafe {
        let res = sysctl(
            mib.as_mut_ptr(),
            mib_length as c_uint,
            addr_of_mut!(cpu_type) as *mut c_void,
            addr_of_mut!(cpu_type_size),
            null_mut(),
            0,
        );
        if res != 0 {
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                "sysctl proc cputype failed",
            ));
        };
    }
    if cpu_type == CPU_TYPE_ANY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid/missing CPU type returned",
        ));
    }

    if cpu_type == CPU_TYPE_ARM64 {
        let mut mib: [c_int; CTL_MAXNAME] = [0; CTL_MAXNAME];
        mib[0] = libc::CTL_KERN;
        mib[1] = libc::KERN_PROC;
        mib[2] = libc::KERN_PROC_PID;
        mib[3] = pid;
        let procinfo = unsafe {
            let mut procinfo = std::mem::MaybeUninit::<kinfo_proc>::zeroed();
            let mut procinfo_size = size_of::<kinfo_proc>();
            let res = sysctl(
                mib.as_mut_ptr(),
                4,
                procinfo.as_mut_ptr() as *mut c_void,
                addr_of_mut!(procinfo_size),
                null_mut(),
                0,
            );
            if res != 0 {
                return Err(std::io::Error::new(
                    std::io::Error::last_os_error().kind(),
                    "sysctl procinfo failed",
                ));
            }
            procinfo.assume_init()
        };
        if procinfo.kp_proc.p_flag & P_TRANSLATED != 0 {
            Ok(CPU_TYPE_X86_64)
        } else {
            Ok(cpu_type)
        }
    } else {
        Ok(cpu_type)
    }
}

pub struct TempFile {
    inner: PathBuf,
}

impl TempFile {
    pub fn from<P: AsRef<Path>>(path: P) -> Self {
        Self {
            inner: path.as_ref().to_path_buf(),
        }
    }

    pub fn random<S: Display>(prefix: S, ext: Option<S>) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write_u128(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap(),
        );
        let ext = ext.map(|s| format!(".{}", s)).unwrap_or_else(String::new);
        Self::from(PathBuf::from(format!(
            "/tmp/{}-{:x}{}",
            prefix,
            hasher.finish(),
            ext
        )))
    }
}

impl !Clone for TempFile {}

impl Deref for TempFile {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for TempFile {
    // Can't really do anything if the file isn't deletable, so ignore errors
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        std::fs::remove_file(&self.inner);
    }
}

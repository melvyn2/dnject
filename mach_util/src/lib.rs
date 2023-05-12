#![feature(extern_types)]

//! C-defs which aren't included in mach2, as well as helper classes

// Re-export for macro use
#[doc(hidden)]
pub use mach2::kern_return::KERN_SUCCESS;

/// Wrap a mach API that returns `kern_return_t` to return according `Result`s
#[macro_export]
macro_rules! mach_try {
    ($e:expr) => {{
        let kr = $e;
        if kr == $crate::KERN_SUCCESS {
            Ok(())
        } else {
            let err_str = ::std::format!(
                "`{}` failed with return code 0x{:x}: {}",
                ::std::stringify!($e).split_once('(').unwrap().0,
                kr,
                ::std::ffi::CStr::from_ptr($crate::mach_error::mach_error_string(kr))
                    .to_string_lossy()
            );
            #[cfg(panic = "unwind")]
            let err_str = format!("[{}:{}] {}", file!(), line!(), err_str);
            ::std::result::Result::Err(::std::io::Error::new(::std::io::ErrorKind::Other, err_str))
        }
    }};
}

mod stubs;
pub use stubs::*;

pub mod mach_portal;

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

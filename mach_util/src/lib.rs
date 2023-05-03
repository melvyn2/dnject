#![feature(extern_types)]

/// C-defs which aren't included in mach2, as well as helper classes

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

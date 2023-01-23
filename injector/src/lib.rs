#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
#[cfg(target_os = "freebsd")]
mod posix;

#[cfg(target_os = "windows")]
mod nt;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;

use mach_util::TempFile;

#[cfg(target_os = "macos")]
pub fn spawn_term() -> Result<std::os::fd::OwnedFd, std::io::Error> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStringExt;

    use nix::fcntl::open;
    use nix::unistd::mkfifo;

    // Setup fifo here
    let path = TempFile::random("termspawn", None);
    mkfifo(path.as_path(), nix::sys::stat::Mode::S_IRWXU).map_err(std::io::Error::from)?;

    // Spawn term here
    let cmd = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "tell app \"Terminal\"
    do script \"trap '' SIGINT && (sleep 0.1 && clear && tty > {}) & exec tail -f /dev/null\"
    activate
end tell",
            path.to_string_lossy()
        ))
        .output();
    match cmd {
        Ok(o) if !o.status.success() => Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "osascript did not exit successfully: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        )),
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }?;

    // This will block until the child has sent its tty node path
    let tty_path = {
        let mut bytes = fs::read(path.as_path())?;
        assert_eq!(bytes.pop(), Some(b'\n'));
        PathBuf::from(OsString::from_vec(bytes))
    };

    // Open the tty
    let tty_fd = open(
        &tty_path,
        nix::fcntl::OFlag::O_RDWR,
        nix::sys::stat::Mode::S_IRWXU,
    )
    .map_err(std::io::Error::from)?;

    Ok(unsafe { OwnedFd::from_raw_fd(tty_fd) })
}

#[cfg(not(target_os = "macos"))]
pub fn spawn_term() -> Result<OwnedFd, std::io::Error> {
    todo!()
}

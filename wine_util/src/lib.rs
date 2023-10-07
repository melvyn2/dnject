use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct WineEnv {
    exe: Option<String>,
    loader: PathBuf,
    prefix: Option<PathBuf>,
    env: HashMap<String, String>,
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

impl WineEnv {
    // Can't take existing command because the `program` of a Command can't be changed
    pub fn launch_in<S: AsRef<OsStr>>(&self, program: S, clear_env: bool) -> Command {
        let mut new = Command::new(self.loader.as_os_str());
        new.arg(program);
        if clear_env {
            new.env_clear();
        }
        new.envs(&self.env);
        new
    }

    pub fn wine_loader(&self) -> &Path {
        self.loader.as_path()
    }

    pub fn prefix(&self) -> Option<&Path> {
        self.prefix.as_deref()
    }

    pub fn target_exe(&self) -> Option<&str> {
        self.exe.as_deref()
    }
}

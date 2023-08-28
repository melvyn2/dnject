use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

pub struct WineEnv {
    loader: PathBuf,
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
    // Can't take existing command because can't change `program` of Command
    pub fn launch_in<S: AsRef<OsStr>>(&self, program: S, clear_env: bool) -> Command {
        let mut new = Command::new(self.loader.as_os_str());
        new.arg(program);
        if clear_env {
            new.env_clear();
        }
        new.envs(&self.env);
        new
    }
}

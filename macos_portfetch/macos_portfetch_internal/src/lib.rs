use libc::pid_t;

use bincode::{Decode, Encode};

use mach_util::error::MachError;

#[derive(Encode, Decode)]
pub struct Input {
    pub target: pid_t,
    pub bootstrap_name: String,
}

#[derive(Encode, Decode)]
pub enum StatusMessage {
    Parse(Result<(), String>),
    Connect(Result<(), MachError>),
    TFP(Result<(), MachError>),
    Send(Result<(), MachError>),
}

impl ToString for StatusMessage {
    fn to_string(&self) -> String {
        match self {
            Self::Parse(Ok(())) => "parsed input".to_string(),
            Self::Connect(Ok(())) => "connected to parent mach port".to_string(),
            Self::TFP(Ok(())) => "attached to target port".to_string(),
            Self::Send(Ok(())) => "sent port to parent".to_string(),
            Self::Parse(Err(e)) => format!("failed to parse input: {}", e),
            Self::Connect(Err(e)) => format!("failed to connect to parent mach port: {}", e),
            Self::TFP(Err(e)) => format!("failed to attach to target: {}", e),
            Self::Send(Err(e)) => format!("failed to send port to parent: {}", e),
        }
    }
}

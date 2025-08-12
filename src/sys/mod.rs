

#[cfg(any(target_os = "linux",  target_os = "android"))]
mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
mod windows;



#[derive(Debug)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub enum ProcessError {
    InvalidNetwork,
    NotFound,
    SysctlError(String),
    ProcInfoError(i32),
}

impl std::error::Error for ProcessError {}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProcessError::InvalidNetwork => write!(f, "invalid network protocol"),
            ProcessError::NotFound => write!(f, "process not found"),
            ProcessError::SysctlError(msg) => write!(f, "sysctl error: {}", msg),
            ProcessError::ProcInfoError(code) => write!(f, "proc info error: {}", code),
        }
    }
}
use std::{
    fmt::write,
    io,
    net::{IpAddr, Ipv4Addr},
};

use thiserror::Error;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone, Copy)]
pub struct NetWorkTuple {
    network: Network,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

impl Default for NetWorkTuple {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 0,
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_port: 0,
        }
    }
}

impl NetWorkTuple {
    pub fn new(src_ip: IpAddr, src_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            ..Default::default()
        }
    }

    pub fn new_tcp(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            network: Network::Tcp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("InvalidNetwork")]
    InvalidNetwork,
    #[error("notfound")]
    NotFound,
    #[error("sysctl read error:{0}")]
    SysctlError(String),
    #[error("proc read error:{0}")]
    ProcInfoError(i32),

    #[error("name read error:{0}")]
    NameReadError(String),

    #[error("io error:{0}")]
    IoError(#[from] io::Error),
}

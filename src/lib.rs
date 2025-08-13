
//! Process identification library for network connections
//!
//! This crate provides functionality to identify processes associated with network connections
//! on different operating systems (Windows, macOS, Linux).
//!
//! # Example
//!
//!
//! ```rust
//! use network_utils::process::{NetWorkTuple, find_process_name};
//! use std::net::{IpAddr, Ipv4Addr};
//! 
//!  // Create a network tuple for a TCP connection
//! let tuple = NetWorkTuple::new_tcp(
//! IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080,
//! IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80
//! );
//! 
//!  // Find the process associated with this connection
//!  // Note: This requires appropriate permissions and only works on the local machine
//! // let (pid, process_name) = find_process_name(tuple)?;
pub mod process;
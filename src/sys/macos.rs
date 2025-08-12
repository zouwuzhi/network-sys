use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;

use crate::sys::{Network, ProcessError};

const PROC_PIDPATHINFO: u32 = 0xb;
const PROC_PIDPATHINFOSIZE: usize = 1024;
const PROC_CALLNUMPIDINFO: u32 = 0x2;
// Define SYS_proc_info for macOS (Darwin), based on XNU source
const SYS_PROC_INFO: i32 = 336;


// Determine structure size based on macOS version
fn get_struct_size() -> usize {
    let os_release = sysctl_by_name("kern.osrelease").unwrap_or_default();
    let major = os_release
        .split('.')
        .next()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    
    match major >= 22 {
        true => 408,
        false => 384,
    }
}

fn sysctl_by_name(name: &str) -> io::Result<String> {
    let c_name = CString::new(name)?;
    let mut size: usize = 0;
    
    unsafe {
        let ret = libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let mut buf = vec![0u8; size];
    unsafe {
        let ret = libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let c_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const _) };
    Ok(c_str.to_string_lossy().into_owned())
}

pub fn find_process_name(network: Network, ip: IpAddr, port: u16) -> Result<(u32, String), ProcessError> {
    let spath = match network {
        Network::Tcp => "net.inet.tcp.pcblist_n",
        Network::Udp => "net.inet.udp.pcblist_n",
    };

    let is_ipv4 = matches!(ip, IpAddr::V4(_));

    let buf = sysctl_by_name(spath).map_err(|e| ProcessError::SysctlError(e.to_string()))?;
    let buf = buf.as_bytes();

    let mut item_size = get_struct_size();
    if matches!(network, Network::Tcp) {
        item_size += 208; // sizeof(xtcpcb_n)
    }

    let mut fallback_udp_process = String::new();

    // Skip the first xinpgen (24 bytes) block
    let mut i = 24;
    while i + item_size <= buf.len() {
        let inp = i;
        let so = i + 104; // xsocket_n offset

        // Source port (xinpcb_n.inp_lport)
        let src_port = u16::from_be_bytes([buf[inp + 18], buf[inp + 19]]);
        if port != src_port {
            i += item_size;
            continue;
        }

        // xinpcb_n.inp_vflag
        let flag = buf[inp + 44];

        let src_ip = match (flag & 0x1 > 0 && is_ipv4, flag & 0x2 > 0 && !is_ipv4) {
            (true, _) => {
                // IPv4
                let addr = Ipv4Addr::new(buf[inp + 76], buf[inp + 77], buf[inp + 78], buf[inp + 79]);
                Some(IpAddr::V4(addr))
            }
            (_, true) => {
                // IPv6
                let addr_bytes = &buf[inp + 64..inp + 80];
                let addr = Ipv6Addr::from([
                    addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                    addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7],
                    addr_bytes[8], addr_bytes[9], addr_bytes[10], addr_bytes[11],
                    addr_bytes[12], addr_bytes[13], addr_bytes[14], addr_bytes[15],
                ]);
                Some(IpAddr::V6(addr))
            }
            _ => None,
        };

        if let Some(src_ip) = src_ip {
            let src_ip = match src_ip {
                IpAddr::V4(addr) => IpAddr::V4(addr),
                IpAddr::V6(addr) => IpAddr::V6(addr.octets().into()),
            };

            if ip == src_ip {
                // xsocket_n.so_last_pid
                let pid = u32::from_ne_bytes([buf[so + 68], buf[so + 69], buf[so + 70], buf[so + 71]]);
                let path = get_exec_path_from_pid(pid)?;
                return Ok((pid, path));
            }

            // UDP fallback for unspecified IP
            if matches!(network, Network::Udp)
                && (src_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED) || src_ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                && is_ipv4 == matches!(src_ip, IpAddr::V4(_))
            {
                let pid = u32::from_ne_bytes([buf[so + 68], buf[so + 69], buf[so + 70], buf[so + 71]]);
                if let Ok(path) = get_exec_path_from_pid(pid) {
                    fallback_udp_process = path;
                }
            }
        }

        i += item_size;
    }

    if matches!(network, Network::Udp) && !fallback_udp_process.is_empty() {
        return Ok((0, fallback_udp_process));
    }

    Err(ProcessError::NotFound)
}

fn get_exec_path_from_pid(pid: u32) -> Result<String, ProcessError> {
    let mut buf = [0u8; PROC_PIDPATHINFOSIZE];
    
    let ret = unsafe {
        libc::syscall(
            SYS_PROC_INFO,
            PROC_CALLNUMPIDINFO,
            pid,
            PROC_PIDPATHINFO,
            0,
            buf.as_mut_ptr() as *mut _,
            PROC_PIDPATHINFOSIZE as u64,
        )
    };

    if ret < 0 {
        return Err(ProcessError::ProcInfoError(ret as i32));
    }

    let c_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const _) };
    Ok(c_str.to_string_lossy().into_owned())
}
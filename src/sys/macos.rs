use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::slice;

use libc::sysctl;
use libproc::bsd_info::BSDInfo;
use libproc::file_info::{ListFDs, ProcFDInfo, ProcFDType, pidfdinfo};
use libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::proc_pid::{self, listpidinfo, pidinfo};
use libproc::processes::{ProcFilter, pids_by_type};
use sysctl::{CtlValue, Sysctl};

use crate::sys::{Network, ProcessError};

const PROC_PIDPATHINFO: u32 = 0xb;
const PROC_PIDPATHINFOSIZE: usize = 1024;
const PROC_CALLNUMPIDINFO: u32 = 0x2;
// Define SYS_proc_info for macOS (Darwin), based on XNU source
const SYS_PROC_INFO: i32 = 336;

/// 获取当前进程的真实 UID
pub fn get_current_process_uid() -> Result<u32, String> {
    let pid = std::process::id() as i32;

    println!("current pid :{pid}");

    // 使用 ProcBsdInfo 获取 UID
    let bsd_info = pidinfo::<BSDInfo>(pid, 0)
        .map_err(|e| format!("无法获取 PID {} 的 BSD 信息: {}", pid, e))?;

    println!("current uid :{}", bsd_info.pbi_ruid);

    Ok(bsd_info.pbi_ruid)
}

// pub fn find_process_name(
//     network: Network,
//     ip: IpAddr,
//     port: u16,
// ) -> Result<(u32, String), ProcessError> {
//     let pid = get_pid_by_source_ip_port(ip, port).unwrap_or_default() as u32;
//     let ss = get_exec_path_from_pid(pid)?;
//     Ok((pid, ss))
// }

fn get_pid_by_source_ip_port(source_ip: IpAddr, source_port: u16) -> Option<i32> {
    // 获取所有进程的 PID

    let proc_filter = match get_current_process_uid() {
        Ok(ruid) => ProcFilter::ByRealUID { ruid },
        Err(e) => ProcFilter::All,
    };

    let pids = match pids_by_type(proc_filter) {
        Ok(pids) => pids,
        Err(e) => {
            eprintln!("Failed to list PIDs: {}", e);
            return None;
        }
    };

    // 遍历每个进程
    for pid in pids {
        let name = get_exec_path_from_pid(pid).unwrap_or_default();
        eprintln!("pid info: pid:{pid} : {name}");

        // 获取进程的所有 socket 文件描述符
        let info = match pidinfo::<BSDInfo>(pid as i32, 0) {
            Ok(info) => info,
            Err(e) => {
                eprintln!("BSDInfo error:{e},pid:{pid}");
                continue;
            }
        };

        eprintln!("pass pid info: pid:{pid} : {name} , uid:{} ", info.pbi_ruid);

        let fds = match listpidinfo::<ListFDs>(pid as i32, info.pbi_nfiles as usize) {
            Ok(fds) => fds,
            Err(e) => {
                eprintln!("list fds error:{e}");
                continue;
            }
        };

        for fd in &fds {
            if let ProcFDType::Socket = fd.proc_fdtype.into() {
                let socket = match pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) {
                    Ok(socket) => socket,
                    Err(e) => {
                        eprintln!("read socket fd error:{e}");
                        continue;
                    }
                };

                if let SocketInfoKind::Tcp = socket.psi.soi_kind.into() {
                    let info = unsafe { socket.psi.soi_proto.pri_tcp };

                    let local_port = u16::from_be(info.tcpsi_ini.insi_lport as u16);

                    if local_port != source_port {
                        continue;
                    }

                    let local_ip = match info.tcpsi_ini.insi_vflag {
                        vflag if vflag & 0x1 > 0 => {
                            let addr =
                                unsafe { info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr };
                            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
                        }
                        vflag if vflag & 0x2 > 0 => {
                            let addr = unsafe { info.tcpsi_ini.insi_laddr.ina_6.s6_addr };
                            IpAddr::V6(Ipv6Addr::from(addr))
                        }
                        _ => continue,
                    };

                    if local_ip == source_ip {
                        return Some(pid as i32);
                    }
                }
            }
        }
    }

    None
}

// Determine structure size based on macOS version
fn get_struct_size() -> usize {

    let os_release = sysctl::Ctl::new("kern.osrelease").expect("Could not get kern.osrevision sysctl");

    let major = os_release.value_string().expect("msg")
        .split('.')
        .next()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);

    match major >= 22 {
        true => 408,
        false => 384,
    }
}

pub fn find_process_name(
    network: Network,
    ip: IpAddr,
    port: u16,
) -> Result<(u32, String), ProcessError> {
    let spath = match network {
        Network::Tcp => "net.inet.tcp.pcblist_n",
        Network::Udp => "net.inet.udp.pcblist_n",
    };

    let is_ipv4 = matches!(ip, IpAddr::V4(_));

    use sysctl::Sysctl;
    // 使用 sysctl crate 读取原始字节数据
    let v = sysctl::Ctl::new(spath)
        .and_then(|v| v.value())
        .map_err(|e| {
            eprintln!("sysctl failed for {}: {}", spath, e);
            ProcessError::SysctlError(e.to_string())
        })?;

    let buf = match v {
        CtlValue::Struct(data) => data,
        _ => {
            return Err(ProcessError::SysctlError(
                "Expected struct data from sysctl".to_string(),
            ));
        }
    };

    if buf.is_empty() {
        eprintln!("sysctl returned empty data for {}", spath);
        return Err(ProcessError::SysctlError(format!(
            "Empty data returned for {}",
            spath
        )));
    }

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
                let addr =
                    Ipv4Addr::new(buf[inp + 76], buf[inp + 77], buf[inp + 78], buf[inp + 79]);
                Some(IpAddr::V4(addr))
            }
            (_, true) => {
                // IPv6
                let addr_bytes = &buf[inp + 64..inp + 80];
                let addr = Ipv6Addr::from([
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                    addr_bytes[4],
                    addr_bytes[5],
                    addr_bytes[6],
                    addr_bytes[7],
                    addr_bytes[8],
                    addr_bytes[9],
                    addr_bytes[10],
                    addr_bytes[11],
                    addr_bytes[12],
                    addr_bytes[13],
                    addr_bytes[14],
                    addr_bytes[15],
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
                let pid =
                    u32::from_ne_bytes([buf[so + 68], buf[so + 69], buf[so + 70], buf[so + 71]]);
                let path = get_exec_path_from_pid(pid)?;
                return Ok((pid, path));
            }

            // UDP fallback for unspecified IP
            if matches!(network, Network::Udp)
                && (src_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    || src_ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                && is_ipv4 == matches!(src_ip, IpAddr::V4(_))
            {
                let pid =
                    u32::from_ne_bytes([buf[so + 68], buf[so + 69], buf[so + 70], buf[so + 71]]);
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
    let path = proc_pid::pidpath(pid as i32).map_err(|e| ProcessError::ProcInfoError(-1))?;
    Ok(path)
}

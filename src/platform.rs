#[cfg(target_os = "windows")]
mod platform {
    use std::path::PathBuf;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;
    use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use windows::core::HSTRING;

    // 获取 TCP 连接对应的进程 ID
    pub fn get_process_id_by_local_port(local_port: u16) -> anyhow::Result<u32> {
        let mut buffer_size: u32 = 0;
        let mut buffer: Vec<u8>;

        // 第一次调用以获取所需缓冲区大小
        unsafe {
            GetExtendedTcpTable(
                None,
                &mut buffer_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        buffer = vec![0u8; buffer_size as usize];
        let table = buffer.as_mut_ptr() as *mut MIB_TCPTABLE_OWNER_PID;

        // 获取 TCP 表
        unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as _),
                &mut buffer_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        // 安全地解引用 table
        let table = unsafe { &*table };
        // 正确访问 table 数组
        let rows = unsafe {
            std::slice::from_raw_parts(
                table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID, // 使用正确的指针
                table.dwNumEntries as usize,
            )
        };

        // 查找匹配的本地端口
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            if port == local_port {
                return Ok(row.dwOwningPid);
            }
        }

        Err(anyhow::anyhow!("No process found for port {}", local_port))
    }

    // 获取进程的可执行文件路径
    pub fn get_process_path(pid: u32) -> anyhow::Result<PathBuf> {
        let current_pid = unsafe { GetCurrentProcessId() };

        if pid == 0 || pid == current_pid {
            return Err(anyhow::anyhow!(
                "Invalid or current process {pid},{current_pid}"
            ));
        }

        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
        let mut buffer: [u16; 1024] = [0; 1024];
        let len = unsafe { GetModuleFileNameExW(handle, None, &mut buffer) };
        unsafe { CloseHandle(handle)? };

        if len == 0 {
            return Err(anyhow::anyhow!("Failed to get process path"));
        }

        let path = HSTRING::from_wide(&buffer[..len as usize])?.to_string();
        Ok(PathBuf::from(path))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use sysctl::Sysctl;

    // 模拟 struct xtcpcb 的字段（简化为示例，实际需根据内核定义）
    #[repr(C)]
    #[derive(Debug)]
    struct TcpPcb {
        _padding1: [u8; 24], // 假设偏移到本地端口
        local_port: u16,     // 本地端口（大端序）
        _padding2: [u8; 22], // 假设偏移到 PID
        pid: u32,            // 进程 ID
        _padding3: [u8; 80], // 填充到大致 128 字节
    }

    pub fn get_process_id_by_local_port(local_port: u16) -> Result<u32> {
        let ctl = sysctl::Ctl::new("net.inet.tcp.pcblist")
            .context("Failed to access sysctl net.inet.tcp.pcblist")?;
        let value = ctl.value().context("Failed to read sysctl value")?;

        if let sysctl::SysctlValue::Raw(raw) = value {
            let data = raw.as_slice();
            // 跳过 xinpgen 头部（通常 24 字节，视内核版本而定）
            let mut offset = 24;
            while offset + std::mem::size_of::<TcpPcb>() <= data.len() {
                let pcb = unsafe { &*(data.as_ptr().add(offset) as *const TcpPcb) };
                let port = u16::from_be(pcb.local_port);
                if port == local_port && pcb.pid != 0 {
                    return Ok(pcb.pid);
                }
                offset += std::mem::size_of::<TcpPcb>();
            }
        }

        Err(anyhow::anyhow!("No process found for port {}", local_port))
    }

    pub fn get_process_path(pid: u32) -> Result<PathBuf> {
        if pid == 0 || pid == std::process::id() {
            return Err(anyhow::anyhow!("Invalid or current process {}", pid));
        }

        let path = libproc::libproc::proc_pid::pidpath(pid as i32)
            .context("Failed to get process path")?;
        Ok(PathBuf::from(path))
    }
}

// #[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::io::{self, BufRead};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};


/// 根据本地 IP 和端口获取进程 ID（PID）。
/// 返回 `Ok(Some(pid))` 如果找到，`Ok(None)` 如果未找到，`Err` 如果出错。
// async fn get_process_id_by_local_port(local_ip: &str, local_port: u16) -> io::Result<Option<u32>> {
//     let local_ip = local_ip
//         .parse::<Ipv4Addr>()
//         .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IP: {}", e)))?;

//     // 在 spawn_blocking 中执行 Netlink 操作（同步调用）
//     let (inode, _uid) = tokio::task::spawn_blocking(move || -> io::Result<(u32, u32)> {
//         // 创建 Netlink socket
//         let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
//         let addr = SocketAddr::new(0, 0);
//         socket.bind_auto()?;
//         socket.connect(&addr)?;

//         // 构建请求
//         let mut header = NetlinkHeader::default();
//         header.flags = NLM_F_REQUEST | NLM_F_DUMP;
//         header.message_type = SOCK_DIAG_BY_FAMILY;

//         let sockid = SocketId {
//             source_port: local_port.to_be(),
//             destination_port: 0,
//             source_address: IpAddr::V4(local_ip).into(),
//             destination_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED).into(),
//             interface_id: 0,
//             cookie: [0; 8],
//         };

//         let req = InetRequest {
//             family: AF_INET,
//             protocol: IPPROTO_TCP as u8, // 可改为 IPPROTO_UDP
//             extensions: ExtensionFlags::INFO,
//             states: StateFlags::all(), // 所有状态
//             socket_id: sockid,
//         };

//         let mut packet = NetlinkMessage::new(header, SockDiagMessage::InetRequest(req).into());

//         packet.finalize();

//         let mut buf = vec![0; packet.header.length as usize];

//         assert_eq!(buf.len(), packet.buffer_len());

//         packet.serialize(&mut buf[..]);
//         println!(">>> {packet:?}");

//         if let Err(e) = socket.send(&buf[..], 0) {
//             println!("SEND ERROR {e}");
//             return Err(e);
//         }

//         let mut receive_buffer = vec![0; 4096];
//         let mut offset = 0;
//         let mut found_inode = 0u32;
//         let mut found_uid = 0u32;

//         loop {
//             let size = socket.recv(&mut &mut receive_buffer[..], 0)?;
//             loop {
//                 let bytes = &receive_buffer[offset..];

//                 let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes)
//                     .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//                 println!("<<< {rx_packet:?}");

//                 if rx_packet.header.message_type == NLMSG_DONE {
//                     break;
//                 }

//                 if rx_packet.header.message_type == NLMSG_ERROR {
//                     return Err(io::Error::new(
//                         io::ErrorKind::Other,
//                         "Netlink error response",
//                     ));
//                 }

//                 if let NetlinkPayload::InnerMessage(InetResponse::GetSockDiag(msg)) = rx_packet.payload {
//                     if msg.socket_id.source_port.to_be() == local_port
//                         && msg.socket_id.source_address == IpAddr::V4(local_ip).into()
//                     {
//                         found_inode = msg.inode;
//                         found_uid = msg.uid;
//                         break;
//                     }
//                 }

//                 offset += rx_packet.header.length as usize;
//                 if offset >= size || rx_packet.header.length == 0 {
//                     offset = 0;
//                     break;
//                 }
//             }
//             if found_inode != 0 {
//                 break;
//             }
//         }

//         Ok((found_inode, found_uid))
//     })
//     .await??;

//     if inode == 0 {
//         return Ok(None); // 未找到匹配的套接字
//     }

//     // 查找 inode 对应的 PID
//     let mut proc_dir = tokio::fs::read_dir("/proc").await?;
//     while let Some(entry) = proc_dir.next_entry().await? {
//         let path = entry.path();
//         if !path.is_dir() {
//             continue;
//         }
//         let file_name = match path.file_name() {
//             Some(name) => name.to_str().unwrap_or(""),
//             None => continue,
//         };
//         if !file_name.chars().all(char::is_numeric) {
//             continue;
//         }

//         let fd_path = path.join("fd");
//         let Ok(mut fd_entries) = tokio::fs::read_dir(&fd_path).await else {
//             continue;
//         };
//         while let Some(fd_entry) = fd_entries.next_entry().await? {
//             let fd_file_path = fd_entry.path();
//             let Ok(link) = tokio::fs::read_link(&fd_file_path).await else {
//                 continue;
//             };
//             if let Some(link_str) = link.to_str() {
//                 if link_str.starts_with("socket:[") {
//                     let inode_str = &link_str[8..link_str.len() - 1];
//                     if let Ok(found_inode) = inode_str.parse::<u32>() {
//                         if found_inode == inode {
//                             let pid = file_name.parse::<u32>().map_err(|e| {
//                                 io::Error::new(
//                                     io::ErrorKind::InvalidData,
//                                     format!("Invalid PID: {}", e),
//                                 )
//                             })?;
//                             return Ok(Some(pid));
//                         }
//                     }
//                 }
//             }
//         }
//     }

//     Ok(None) // 未找到匹配的 PID
// }

    pub fn get_process_path(pid: u32) -> Result<PathBuf> {
        if pid == 0 || pid == std::process::id() {
            return Err(anyhow::anyhow!("Invalid or current process {}", pid));
        }

        let path =
            fs::read_link(format!("/proc/{}/exe", pid)).context("Failed to get process path")?;
        Ok(path)
    }
}

// 主程序使用 platform 模块
pub use platform::{get_process_id_by_local_port, get_process_path};

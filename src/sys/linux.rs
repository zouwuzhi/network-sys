use std::io::{self, BufRead};
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::anyhow;
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};
use tokio::process::Command;

/// 根据本地 IP 和端口获取进程 ID（PID）。
/// 返回 `Ok(Some(pid))` 如果找到，`Ok(None)` 如果未找到，`Err` 如果出错。
pub async fn get_process_id_by_local_port(
    local_ip: IpAddr,
    local_port: u16,
) -> io::Result<Option<u32>> {
    let mut instant = Instant::now();

    // 在 spawn_blocking 中执行 Netlink 操作（同步调用）
    let (inode, _uid) = tokio::task::spawn_blocking(move || -> io::Result<(u32, u32)> {
        // 创建 Netlink socket
        let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
        let addr = SocketAddr::new(0, 0);
        socket.bind_auto()?;
        socket.connect(&addr)?;

        println!(">>> {local_ip:?},{local_port:?}");

        // 构建请求
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        header.message_type = SOCK_DIAG_BY_FAMILY;

        let sockid = SocketId {
            source_port: local_port,
            destination_port: 1080,
            source_address: local_ip.clone(),
            destination_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)).into(),
            interface_id: 0,
            cookie: [0; 8],
        };

        let req = InetRequest {
            family: AF_INET,
            protocol: IPPROTO_TCP as u8, // 可改为 IPPROTO_UDP
            extensions: ExtensionFlags::INFO,
            states: StateFlags::all(), // 所有状态
            socket_id: sockid,
        };

        let mut packet = NetlinkMessage::new(header, SockDiagMessage::InetRequest(req).into());

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        assert_eq!(buf.len(), packet.buffer_len());

        packet.serialize(&mut buf[..]);
        println!(">>> {packet:?}");

        if let Err(e) = socket.send(&buf[..], 0) {
            println!("SEND ERROR {e}");
            return Err(e);
        }

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;
        let mut found_inode = 0u32;
        let mut found_uid = 0u32;

        let ip_clone = local_ip.clone();

        loop {
            let size = socket.recv(&mut &mut receive_buffer[..], 0)?;
            loop {
                let bytes = &receive_buffer[offset..];

                let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                println!("<<< {rx_packet:?}");

                if let NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(msg)) =
                    rx_packet.payload
                {
                    let head = &msg.header;

                    if head.socket_id.source_port == local_port
                        && head.socket_id.source_address == ip_clone
                    {
                        found_inode = head.inode;
                        found_uid = head.uid;
                        break;
                    }
                }

                offset += rx_packet.header.length as usize;
                if offset >= size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
            if found_inode != 0 {
                break;
            }
        }

        Ok((found_inode, found_uid))
    })
    .await??;

    if inode == 0 {
        return Ok(None); // 未找到匹配的套接字
    }

    println!("inode time >> {} micros", instant.elapsed().as_micros());
    instant = Instant::now();

    // 查找 inode 对应的 PID
    let mut proc_dir = tokio::fs::read_dir("/proc").await?;
    while let Some(entry) = proc_dir.next_entry().await? {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let file_name = match path.file_name() {
            Some(name) => name.to_str().unwrap_or(""),
            None => continue,
        };
        if !file_name.chars().all(char::is_numeric) {
            continue;
        }

        let fd_path = path.join("fd");
        let Ok(mut fd_entries) = tokio::fs::read_dir(&fd_path).await else {
            continue;
        };
        while let Some(fd_entry) = fd_entries.next_entry().await? {
            let fd_file_path = fd_entry.path();
            let Ok(link) = tokio::fs::read_link(&fd_file_path).await else {
                continue;
            };
            if let Some(link_str) = link.to_str() {
                if link_str.starts_with("socket:[") {
                    let inode_str = &link_str[8..link_str.len() - 1];
                    if let Ok(found_inode) = inode_str.parse::<u32>() {
                        if found_inode == inode {
                            let pid = file_name.parse::<u32>().map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("Invalid PID: {}", e),
                                )
                            })?;

                            println!("pid time >> {} micros", instant.elapsed().as_micros());

                            return Ok(Some(pid));
                        }
                    }
                }
            }
        }
    }

    Ok(None) // 未找到匹配的 PID
}



/// 根据 PID 获取进程可执行文件的路径。
/// 返回 `Ok(Some(path))` 如果找到，`Ok(None)` 如果未找到，`Err` 如果出错。
pub async fn get_process_path(pid: u32) -> io::Result<Option<PathBuf>> {
    let comm_path = format!("/proc/{}/exe", pid);
    match tokio::fs::read_link(&comm_path).await {
        Ok(path) => Ok(Some(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

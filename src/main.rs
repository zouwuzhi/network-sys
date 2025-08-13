mod sys;

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::sys::NetWorkTuple;

use crate::sys::linux::find_process_name;
// use crate::sys::macos::find_process_name;

// 白名单：允许的程序路径
const WHITELIST: &[&str] = &[
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Windows\System32\curl.exe",
    r"/usr/bin/curl",
    r"/Applications/Google Chrome.app",
    r"/Applications/Visual Studio Code.app",
    r"Lark Helper",
    r"Code Helper",
    r"Google Chrome Helper",
    r"curl",
];

// 获取 TCP 连接对应的进程 ID

// 检查进程是否在白名单中
fn is_process_allowed(process_path: &PathBuf) -> bool {
    let path_str = process_path.to_string_lossy().to_lowercase();
    WHITELIST.iter().any(|&p| p.to_lowercase() == path_str)
}

async fn handle_client(mut stream: TcpStream, whitelist: &HashSet<String>) -> Result<()> {
    let peer_addr = stream.peer_addr().context("Failed to get peer address")?;

    let local_addr = stream.local_addr().context("Failed to get local address")?;

    // 获取客户端进程 ID

    let instant = Instant::now();

    let tuple = NetWorkTuple::new_tcp(peer_addr.ip(), peer_addr.port(), peer_addr.ip(), 1080);

    let (pid, pname) = find_process_name(tuple)?;

    println!(
        "get_process_path from :pid :{pid} pname:{pname}, {:?} to {:?} ({}mics)",
        peer_addr,
        local_addr,
        instant.elapsed().as_micros()
    );

    // 检查是否在白名单中
    if !whitelist.contains(&pname.to_lowercase()) {
        println!("Blocked process:pid:{pid}, {:?}", pname);
        return Err(anyhow::anyhow!("Process not in whitelist"));
    }
    println!("Allowed process: pid:{pid}, {:?}", pname);

    // SOCKS5 协议处理
    let mut buffer = [0u8; 256];
    stream.read(&mut buffer).await?;

    // 检查 SOCKS5 版本和认证方法
    if buffer[0] != 5 {
        return Err(anyhow::anyhow!("Unsupported SOCKS version"));
    }
    let nmethods = buffer[1] as usize;
    let methods = &buffer[2..2 + nmethods];

    // 假设支持无认证
    if !methods.contains(&0) {
        return Err(anyhow::anyhow!("No acceptable auth methods"));
    }

    // 响应无认证
    stream.write_all(&[5, 0]).await?;

    // 处理 SOCKS5 请求
    let mut req = [0u8; 256];
    stream.read(&mut req).await?;

    if req[0] != 5 || req[1] != 1 {
        // 只支持 CONNECT 命令
        return Err(anyhow::anyhow!("Unsupported command"));
    }

    // 解析目标地址
    let (dst_addr, dst_port) = match req[3] {
        1 => {
            // IPv4
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(req[4], req[5], req[6], req[7]));
            let port = u16::from_be_bytes([req[8], req[9]]);
            (ip, port)
        }
        4 => {
            // IPv6
            let ip = IpAddr::V6(std::net::Ipv6Addr::new(
                u16::from_be_bytes([req[4], req[5]]),
                u16::from_be_bytes([req[6], req[7]]),
                u16::from_be_bytes([req[8], req[9]]),
                u16::from_be_bytes([req[10], req[11]]),
                u16::from_be_bytes([req[12], req[13]]),
                u16::from_be_bytes([req[14], req[15]]),
                u16::from_be_bytes([req[16], req[17]]),
                u16::from_be_bytes([req[18], req[19]]),
            ));
            let port = u16::from_be_bytes([req[20], req[21]]);
            (ip, port)
        }
        _ => return Err(anyhow::anyhow!("Unsupported address type")),
    };

    // 连接目标服务器
    let mut target = TcpStream::connect((dst_addr, dst_port))
        .await
        .context("Failed to connect to target")?;

    // 发送成功响应
    let reply = [
        5, 0, 0, 1, 0, 0, 0, 0, 0, 0, // 绑定地址和端口（0.0.0.0:0）
    ];
    stream.write_all(&reply).await?;

    // 双向数据转发
    tokio::io::copy_bidirectional(&mut stream, &mut target)
        .await
        .context("Bidirectional copy failed")?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化白名单
    let whitelist: HashSet<String> = WHITELIST.iter().map(|s| s.to_lowercase()).collect();

    let listener = TcpListener::bind("127.0.0.1:1080")
        .await
        .context("Failed to bind to address")?;
    println!("SOCKS5 proxy listening on 127.0.0.1:1080");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("Failed to accept connection")?;
        println!("New connection from {}", peer_addr);

        let whitelist = whitelist.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, &whitelist).await {
                // eprintln!("Error handling client {}: {:?}", peer_addr, e);
                eprintln!("Error handling client {}: ", peer_addr);
            }
        });
    }
}

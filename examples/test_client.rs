use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 连接到SOCKS5代理
    let mut stream = TcpStream::connect("127.0.0.1:1080").await?;

    // SOCKS5握手
    // Version 5, 1 method, no authentication
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    // 读取服务器响应
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != 0x05 || response[1] != 0x00 {
        return Err("SOCKS5 handshake failed".into());
    }

    // 发送连接请求 (connect to httpbin.org:80)
    let request = [
        0x05, // SOCKS version
        0x01, // CONNECT command
        0x00, // Reserved
        0x03, // Domain name address type
        0x0E, // Domain length (14)
        b'h', b't', b't', b'p', b'b', b'i', b'n', b'.', b'o', b'r', b'g',
        0x00, 0x50, // Port 80
    ];

    stream.write_all(&request).await?;

    // 读取响应
    let mut response = [0u8; 10];
    stream.read_exact(&mut response).await?;

    if response[1] == 0x00 {
        println!("Connection successful!");

        // 发送HTTP请求测试
        let http_request = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n";
        stream.write_all(http_request).await?;

        // 读取响应
        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer).await?;
        println!("Received {} bytes", n);
        println!("Response: {}", String::from_utf8_lossy(&buffer[..n.min(200)]));
    } else {
        println!("Connection failed with error code: {}", response[1]);
    }

    Ok(())
}
use crate::process::{NetWorkTuple, Network, ProcessError};
use std::net::IpAddr;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::core::HSTRING;

/// 根据网络元组获取进程 ID 和名称
pub fn find_process_name(net_tuple: NetWorkTuple) -> Result<(u32, String), ProcessError> {
    let pid = get_pid_by_net(net_tuple)?;
    let name = get_process_path(pid)?;
    Ok((pid, name))
}

/// 根据网络元组获取进程 ID
fn get_pid_by_net(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    match net_tuple.network {
        Network::Tcp => get_pid_by_tcp_net(net_tuple),
        Network::Udp => get_pid_by_udp_net(net_tuple),
    }
}

/// 获取 TCP 网络连接的进程 ID
fn get_pid_by_tcp_net(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    let af_inet = get_address_family(&net_tuple);

    // 获取 TCP 表数据
    let buffer = get_extended_tcp_table(af_inet)?;

    match net_tuple.src_ip {
        IpAddr::V4(src_ip) => search_tcp_v4_pid(&buffer, src_ip, net_tuple.src_port),
        IpAddr::V6(src_ip) => search_tcp_v6_pid(&buffer, src_ip, net_tuple.src_port),
    }
}

/// 获取 UDP 网络连接的进程 ID
fn get_pid_by_udp_net(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    let af_inet = get_address_family(&net_tuple);

    // 获取 UDP 表数据
    let buffer = get_extended_udp_table(af_inet)?;

    match net_tuple.src_ip {
        IpAddr::V4(src_ip) => search_udp_v4_pid(&buffer, src_ip, net_tuple.src_port),
        IpAddr::V6(src_ip) => search_udp_v6_pid(&buffer, src_ip, net_tuple.src_port),
    }
}

/// 获取地址族
fn get_address_family(net_tuple: &NetWorkTuple) -> u32 {
    if net_tuple.is_v4() {
        AF_INET.0 as u32
    } else {
        AF_INET6.0 as u32
    }
}

/// 获取扩展 TCP 表
fn get_extended_tcp_table(af_inet: u32) -> Result<Vec<u8>, ProcessError> {
    let mut buffer_size: u32 = 0;

    unsafe {
        GetExtendedTcpTable(
            None,
            &mut buffer_size,
            false,
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    let mut buffer = vec![0u8; buffer_size as usize];

    unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as _),
            &mut buffer_size,
            false,
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    Ok(buffer)
}

/// 获取扩展 UDP 表
fn get_extended_udp_table(af_inet: u32) -> Result<Vec<u8>, ProcessError> {
    let mut buffer_size: u32 = 0;

    unsafe {
        GetExtendedUdpTable(
            None,
            &mut buffer_size,
            false,
            af_inet,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }

    let mut buffer = vec![0u8; buffer_size as usize];

    unsafe {
        GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as _),
            &mut buffer_size,
            false,
            af_inet,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    Ok(buffer)
}

/// 搜索 IPv4 TCP 连接的 PID
fn search_tcp_v4_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_u32 = u32::from_be_bytes(src_ip.octets()).to_be();

    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_u32 == row.dwLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 搜索 IPv6 TCP 连接的 PID
fn search_tcp_v6_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_bytes = src_ip.octets();

    let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID,
            table.dwNumEntries as usize,
        )
    };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_bytes == row.ucLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 搜索 IPv4 UDP 连接的 PID
fn search_udp_v4_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_u32 = u32::from_be_bytes(src_ip.octets()).to_be();

    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_u32 == row.dwLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 搜索 IPv6 UDP 连接的 PID
fn search_udp_v6_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_bytes = src_ip.octets();

    let table = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID,
            table.dwNumEntries as usize,
        )
    };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_bytes == row.ucLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 获取进程的可执行文件路径
fn get_process_path(pid: u32) -> Result<String, ProcessError> {
    let current_pid = unsafe { GetCurrentProcessId() };
    if pid == 0 || pid == current_pid {
        return Err(ProcessError::NameReadError(format!(
            "Invalid or current process PID: {pid}, Current PID: {current_pid}"
        )));
    }

    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(|e| {
            ProcessError::NameReadError(format!("OpenProcess failed for PID {pid}: {e}"))
        })?
    };

    let mut buffer: [u16; 1024] = [0; 1024];
    let len = unsafe { GetModuleFileNameExW(handle, None, &mut buffer) };

    unsafe {
        CloseHandle(handle).map_err(|e| {
            ProcessError::NameReadError(format!("CloseHandle failed for PID {pid}: {e}"))
        })?
    };

    if len == 0 {
        return Err(ProcessError::NameReadError(format!(
            "Failed to read process name for PID {pid}"
        )));
    }

    HSTRING::from_wide(&buffer[..len as usize])
        .map_err(|e| {
            ProcessError::NameReadError(format!("HSTRING conversion failed for PID {pid}: {e}"))
        })
        .map(|hstring| hstring.to_string())
}

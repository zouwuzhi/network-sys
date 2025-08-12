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

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    let mut buffer: [u16; 1024] = [0; 1024];
    let len = unsafe { GetModuleFileNameExW(handle, None, &mut buffer) };
    unsafe { CloseHandle(handle)? };

    if len == 0 {
        return Err(anyhow::anyhow!("Failed to get process path"));
    }

    let path = HSTRING::from_wide(&buffer[..len as usize])?.to_string();
    Ok(PathBuf::from(path))
}

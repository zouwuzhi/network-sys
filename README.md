# network-utils

[![Crates.io](https://img.shields.io/crates/v/network-utils)](https://crates.io/crates/network-utils)
[![Documentation](https://docs.rs/network-utils/badge.svg)](https://docs.rs/network-utils)
![License](https://img.shields.io/crates/l/network-utils)

一个用于识别与网络连接相关联的进程的Rust库，支持Windows、macOS和Linux系统。

## 功能

此库提供了一种跨平台的方式来识别与特定网络连接相关联的进程。它特别适用于：

- 网络监控工具
- 防火墙应用
- 网络安全分析工具
- 网络连接管理器

## 平台支持

- Windows
- macOS
- Linux

## 使用方法

在你的 [Cargo.toml]() 中添加依赖：

```
 [dependencies]
  network-utils = "0.1"
```

## 运行示例

项目包含示例，演示如何使用该库：

```bash
运行process_test示例
cargo run --example process_test
```
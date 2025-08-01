# 高性能多线程网络端口扫描器

一个基于C语言开发的高性能多线程网络端口扫描器，支持SYN半开放扫描和TCP连接扫描两种模式。

## 特性

- **双模式扫描**：
  - TCP Connect扫描：使用系统网络API进行连接测试
  - SYN半开放扫描：发送SYN包进行快速端口检测（需要root权限）
  - 智能源IP选择：自动获取最优路由的本地IP地址

- **高性能**：
  - 多线程并发扫描（最多256个线程）
  - 动态端口列表支持：无1024端口限制，支持全端口扫描（1-65535）
  - 智能批处理和速率控制
  - 优化的网络超时设置
  - 性能接近nmap的SYN扫描能力

- **灵活的目标定义**：
  - 支持单个IP、IP范围、CIDR格式
  - 支持端口列表和端口范围
  - 支持逗号分隔的多目标
  - 动态内存分配，无端口数量限制

- **专业功能**：
  - UDPXY服务专门检测
  - 真正的半开连接SYN扫描
  - 详细的调试信息和包解析
  - 结果文件输出
  - 静默和快速模式

## 编译

### 基本编译
```bash
make
```

### 调试版本
```bash
make debug
```

### 系统安装（可选）
```bash
sudo make install
```

## 使用方法

### 基本语法
```bash
./portscanner <ip> <start_port> <end_port> [选项]
```

### IP格式支持
```bash
# 单个IP
./portscanner 192.168.1.1 80 443

# IP范围
./portscanner 192.168.1.1-192.168.1.254 22 80

# CIDR格式
./portscanner 192.168.1.0/24 80 443

# 多个IP组合
./portscanner -ip "192.168.1.1,192.168.2.1-192.168.2.10,10.0.0.0/24" -ports "22,80,443,8080"
```

### 扫描模式

#### TCP连接扫描（默认）
```bash
./portscanner 192.168.1.1 1-1000 -mode tcp
```

#### SYN半开放扫描（需要root权限）
```bash
sudo ./portscanner 192.168.1.1 1-1000 -mode syn
```

## 性能对比

基于实际测试，两种扫描模式的性能对比：

| 扫描模式 | 适用场景 | 性能表现 | 隐蔽性 | 权限要求 |
|---------|----------|----------|--------|----------|
| **TCP连接** | 通用网络扫描 | 优秀 | 一般 | 普通用户 |
| **SYN扫描** | 大规模/局域网扫描 | 优秀+ | 高 | root权限 |

**性能测试结果**：
- 小规模扫描（<100端口）：两种模式性能相当（~1.0秒）
- 中等规模扫描（100-1000端口）：SYN扫描略有优势
- 大规模扫描（>1000端口）：SYN扫描在并发性能上更优
- 本地网络扫描：SYN扫描检测速度更快

### 常用选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-ip <list>` | IP地址列表 | 使用位置参数 |
| `-ports <list>` | 端口列表 | 使用位置参数 |
| `-mode <tcp\|syn>` | 扫描模式 | tcp |
| `-t <num>` | 线程数 | 50 |
| `-cto <ms>` | 连接超时(毫秒) | 500 |
| `-rto <ms>` | 接收超时(毫秒) | 2000 |
| `-out <file>` | 输出文件 | 无 |
| `-udpxy` | 启用UDPXY检测 | 关闭 |
| `-v` | 详细模式 | 关闭 |
| `-d` | 调试模式 | 关闭 |
| `-fast` | 快速模式 | 关闭 |
| `-q` | 静默模式 | 关闭 |

### 使用示例

#### 基本端口扫描
```bash
# 扫描单个主机的常用端口
./portscanner 192.168.1.1 1 1000

# 扫描整个网段的SSH端口
./portscanner 192.168.1.0/24 22 22

# 全端口SYN扫描（新功能：支持全部65535端口）
sudo ./portscanner 192.168.1.1 1 65535 -mode syn -fast -q
```

#### 大规模端口扫描
```bash
# 扫描5000个端口（突破了原1024端口限制）
sudo ./portscanner 203.0.113.100 4000 9000 -mode syn

# 快速扫描大量端口
sudo ./portscanner target.com 1 10000 -mode syn -fast -t 80
```

#### 性能优化示例
```bash
# 针对速度优化的SYN扫描
sudo ./portscanner 192.168.1.0/24 1-1000 -mode syn -fast -t 100 -cto 300

# 针对准确性优化的TCP连接扫描
./portscanner 192.168.1.1 80,443,22,21 -mode tcp -cto 2000 -rto 5000
```

#### UDPXY服务发现
```bash
# 扫描UDPXY服务（常用于IPTV）
./portscanner 192.168.1.0/24 4000 4010 -udpxy -out udpxy_results.txt

# 快速静默UDPXY扫描
./portscanner 192.168.1.0/24 4000 4010 -udpxy -fast -q -out results.txt
```

#### 高级扫描
```bash
# SYN扫描（需要root权限）- 推荐用于大规模扫描
sudo ./portscanner 10.0.0.0/8 22,80,443 -mode syn -t 100

# 多IP多端口扫描 - 支持无限端口数量
./portscanner -ip "192.168.1.1-192.168.1.50,10.0.0.1" -ports "22,80,443,8080,8000-8100" -out scan_results.txt

# 调试模式详细扫描 - 查看SYN包交互过程
sudo ./portscanner 192.168.1.1 80 443 -mode syn -d -v

# 隐蔽扫描 - SYN扫描不完成三次握手
sudo ./portscanner target.com 1-1000 -mode syn -t 20 -cto 3000
```

## 权限要求

- **TCP Connect扫描**：无特殊权限要求
- **SYN扫描**：需要root权限来创建原始套接字

### 设置SUID（可选，谨慎使用）
```bash
sudo chown root:root portscanner
sudo chmod +s portscanner
```

## 性能调优

### 大规模扫描建议
```bash
# 大网段快速SYN扫描 - 突破端口限制
sudo ./portscanner 10.0.0.0/16 1-5000 -mode syn -fast -t 200 -cto 200 -q

# 全端口扫描 - 新功能支持完整端口范围
sudo ./portscanner target.com 1-65535 -mode syn -fast -t 150

# 降低检测率的隐蔽SYN扫描
sudo ./portscanner target.com 1-1000 -mode syn -t 10 -cto 5000
```

### 扫描模式选择指南
```bash
# 本地/局域网扫描 - 推荐SYN模式
sudo ./portscanner 192.168.1.0/24 1-1000 -mode syn

# 外部网络扫描 - 两种模式性能相当
./portscanner external.target.com 80,443,22 -mode tcp
sudo ./portscanner external.target.com 80,443,22 -mode syn

# 服务检测扫描 - 推荐TCP模式
./portscanner target 80,443 -mode tcp -udpxy

# 大规模快速扫描 - 推荐SYN模式
sudo ./portscanner targets 1-10000 -mode syn -fast
```

### 线程数选择指南
- **小规模扫描**（<100个目标）：10-50线程
- **中等规模扫描**（100-1000个目标）：50-100线程  
- **大规模扫描**（>1000个目标）：100-200线程
- **全端口扫描**（1-65535端口）：150-200线程（SYN模式）
- **网络受限环境**：10-30线程

### 新功能亮点
- **无端口限制**：支持扫描完整的65535端口范围
- **智能源IP**：自动选择最优网络路由的源IP地址
- **真正SYN扫描**：完整的SYN包发送和响应解析
- **动态内存**：根据扫描规模动态分配内存

## 输出格式

### 控制台输出
```
开始扫描 1 个IP，5001 个端口，共 5001 个任务，使用 40 个线程
扫描模式: SYN扫描
[+] 203.0.113.100:4000 端口开放
[+] 203.0.113.100:5201 端口开放
[+] 203.0.113.100:8000 端口开放
[调试] 203.0.113.100:8000 收到SYN-ACK，端口开放
进度: 5001/5001 (100.0%) | 发现开放端口: 28
扫描完成！总共处理了 5001 个任务

=== 扫描结果摘要 ===
发现开放端口: 28
扫描成功率: 0.6%
```

### 文件输出
```
192.168.1.1:22
192.168.1.1:80
192.168.1.100:4000
```

## 技术特性

### 扫描技术
- **TCP Connect**：完整的三次握手连接测试
- **SYN扫描**：半开放扫描，发送SYN包检测端口状态
  - 真正的SYN包构造和发送
  - 专用响应监听线程
  - SYN-ACK和RST包解析
  - 智能源IP地址选择
- **超时控制**：可配置的连接和接收超时
- **并发控制**：智能的线程池和任务队列管理

### 网络优化
- 非阻塞套接字操作
- 原始套接字的高效利用
- 连接重用和资源管理
- 自适应的延迟控制
- 批处理任务分发
- 动态内存分配优化

### 技术创新
- **突破端口限制**：从1024端口扩展到65535全端口支持
- **智能路由检测**：自动获取到目标的最优源IP地址
- **真正SYN实现**：不是简单的connect()调用，而是真正的SYN包操作
- **性能接近nmap**：在本地网络扫描中达到与nmap相当的性能

## 故障排除

### 常见问题

**Q: SYN扫描不工作**
A: 确保以root权限运行，并检查系统是否支持原始套接字。程序会自动回退到TCP模式。

**Q: 扫描速度慢**
A: 尝试使用 `-fast` 选项，或调整 `-t`（线程数）和 `-cto`（超时）参数。SYN模式通常更快。

**Q: 显示"当前版本最多支持1024个端口"**
A: 请使用最新版本，新版本已支持全端口扫描（1-65535）。

**Q: 大量"连接被拒绝"错误**
A: 目标可能有连接限制，尝试减少线程数或增加延迟，或使用SYN模式。

**Q: 无法检测到已知开放的端口**  
A: 检查防火墙设置，尝试增加超时时间，或对比TCP和SYN两种模式的结果。

**Q: SYN扫描显示"过滤"状态**
A: 可能是网络防火墙过滤了SYN包，这是正常现象。可以尝试TCP模式对比。

### 调试技巧
```bash
# 启用详细调试信息（查看SYN包交互）
sudo ./portscanner target 80 80 -mode syn -d -v

# 测试单个端口的SYN扫描
sudo ./portscanner target 80 80 -mode syn -t 1 -d

# 对比两种扫描模式
./portscanner target 80 80 -mode tcp -d
sudo ./portscanner target 80 80 -mode syn -d

# 检查网络连通性
ping target
telnet target 80
nmap -sS -p 80 target  # 对比nmap的SYN扫描结果
```

## 法律声明

此工具仅用于合法的网络安全测试和系统管理目的。使用者有责任确保：

1. 只在拥有授权的网络和系统上使用
2. 遵守当地法律法规
3. 不用于恶意攻击或未授权的网络扫描
4. 注意扫描频率，避免影响目标系统正常运行

## 开发信息

- **语言**：C (POSIX兼容)
- **依赖**：pthread, 标准网络库
- **平台**：Linux, Unix, macOS
- **许可**：MIT License

## 贡献

欢迎提交问题报告和功能请求。在贡献代码时，请确保：

1. 遵循现有的代码风格
2. 添加适当的错误处理
3. 更新相关文档
4. 测试在不同平台上的兼容性

---

**注意**：SYN扫描功能需要原始套接字权限，在某些受限环境中可能无法使用。程序会自动回退到TCP连接扫描模式。

## 更新日志

### v2.0 - 重大功能更新
- ✅ **突破端口限制**：支持全端口扫描（1-65535），移除了1024端口限制
- ✅ **真正SYN扫描**：实现完整的SYN包发送和响应解析机制
- ✅ **智能源IP选择**：自动获取到目标的最优路由源IP地址
- ✅ **性能优化**：SYN扫描性能接近nmap水平
- ✅ **动态内存管理**：根据扫描规模自动分配内存
- ✅ **增强调试**：详细的SYN包交互调试信息

### v1.0 - 基础功能
- TCP连接扫描
- 多线程支持
- UDPXY检测
- 基础SYN扫描框架

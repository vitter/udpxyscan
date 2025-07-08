# 项目信息

## 版本信息
- **项目名称**: 高性能多线程网络端口扫描器
- **版本**: 1.0.0
- **开发语言**: C
- **编译器**: GCC (MinGW-w64 推荐)
- **目标平台**: Windows / Linux

## 项目结构
```
udpxyscan/
├── portscanner.c           # 主程序源码
├── portscanner.exe         # 编译后的可执行文件
├── Makefile               # 构建配置 (Linux)
├── README.md              # 项目文档
├── examples.conf          # 使用示例配置
├── build_test.bat         # Windows构建脚本
├── build_test.sh          # Linux构建脚本
├── test_suite.bat         # 自动化测试脚本
├── dev_tools.bat          # 开发者工具
└── .vscode/               # VS Code配置
    ├── tasks.json         # 构建任务
    ├── launch.json        # 调试配置
    ├── settings.json      # 编辑器设置
    └── extensions.json    # 推荐扩展
```

## 技术特性
- ✅ 双模式扫描 (TCP Connect / SYN Half-Open)
- ✅ 多线程并发 (最多256线程)
- ✅ 跨平台兼容 (Windows/Linux)
- ✅ 原始套接字支持
- ✅ UDPXY服务检测
- ✅ 灵活的IP/端口输入格式
- ✅ 批量扫描和文件输出
- ✅ 性能优化和速率控制

## 开发环境
- **编译器**: GCC 9.0+ (推荐 MinGW-w64)
- **调试器**: GDB
- **编辑器**: Visual Studio Code
- **版本控制**: Git (可选)

## 依赖库
- pthread (多线程)
- winsock2 (Windows网络API)
- netinet (Linux网络API)

## 编译选项
- `-Wall -Wextra`: 启用所有警告
- `-O2`: 优化等级2
- `-pthread`: 启用多线程支持
- `-g`: 调试信息 (调试版本)
- `-DDEBUG`: 调试宏定义

## 测试覆盖
- [x] 基本TCP连接扫描
- [x] 多线程并发测试
- [x] 超时和错误处理
- [x] 文件输出功能
- [x] 参数解析验证
- [x] UDPXY服务检测
- [x] 网段和范围扫描
- [x] SYN扫描 (需要管理员权限)
- [ ] 性能压力测试
- [ ] 大规模网络扫描

## 性能指标
- **线程数**: 1-256 (默认50)
- **连接超时**: 500-5000ms (默认500ms)
- **扫描速度**: ~1000 端口/秒 (局域网)
- **内存使用**: <10MB (典型使用)
- **CPU使用**: 中等 (多线程并发)

## 安全考虑
- 原始套接字需要管理员权限
- 实现了速率限制防止网络拥塞
- 输入验证防止缓冲区溢出
- 超时机制防止挂起
- 遵循网络使用最佳实践

## 许可证
MIT License - 开源自由使用

## 作者
vitter - 2025

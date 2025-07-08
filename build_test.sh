#!/bin/bash

echo "=== 高性能端口扫描器编译测试 ==="

# 检查编译器
if ! command -v gcc &> /dev/null; then
    echo "错误: 未找到gcc编译器"
    exit 1
fi

echo "✓ 找到gcc编译器"

# 编译程序
echo "正在编译portscanner..."
if gcc -Wall -Wextra -O2 -pthread -o portscanner portscanner.c; then
    echo "✓ 编译成功"
else
    echo "✗ 编译失败"
    exit 1
fi

# 检查可执行文件
if [ -f "portscanner" ]; then
    echo "✓ 可执行文件已生成"
    ls -la portscanner
else
    echo "✗ 可执行文件未生成"
    exit 1
fi

# 显示帮助信息
echo ""
echo "=== 程序帮助信息 ==="
./portscanner

echo ""
echo "=== 编译测试完成 ==="
echo "程序已准备就绪，可以开始扫描！"
echo ""
echo "示例用法："
echo "  基本扫描:     ./portscanner 127.0.0.1 80 443"
echo "  网段扫描:     ./portscanner 192.168.1.0/24 22 22"
echo "  UDPXY检测:    ./portscanner 192.168.1.1 4000 4010 -udpxy"
echo "  SYN扫描:      sudo ./portscanner 192.168.1.1 1-1000 -mode syn"

@echo off
echo === 高性能端口扫描器编译测试 ===

REM 检查是否有gcc编译器
gcc --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误: 未找到gcc编译器
    echo 请安装MinGW-w64或TDM-GCC
    pause
    exit /b 1
)

echo ✓ 找到gcc编译器

REM 编译程序
echo 正在编译portscanner...
gcc -Wall -Wextra -O2 -pthread -o portscanner.exe portscanner.c
if %errorlevel% neq 0 (
    echo ✗ 编译失败
    pause
    exit /b 1
)

echo ✓ 编译成功

REM 检查可执行文件
if exist portscanner.exe (
    echo ✓ 可执行文件已生成
    dir portscanner.exe
) else (
    echo ✗ 可执行文件未生成
    pause
    exit /b 1
)

REM 显示帮助信息
echo.
echo === 程序帮助信息 ===
portscanner.exe

echo.
echo === 编译测试完成 ===
echo 程序已准备就绪，可以开始扫描！
echo.
echo 示例用法：
echo   基本扫描:     portscanner.exe 127.0.0.1 80 443
echo   网段扫描:     portscanner.exe 192.168.1.0/24 22 22
echo   UDPXY检测:    portscanner.exe 192.168.1.1 4000 4010 -udpxy
echo   注意: Windows上的SYN扫描需要管理员权限和WinPcap

pause

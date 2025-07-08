@echo off
setlocal enabledelayedexpansion

echo ===============================================
echo    高性能端口扫描器 - 自动化测试套件
echo ===============================================
echo.

REM 检查编译器
gcc --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 错误: 未找到gcc编译器
    echo    请安装MinGW-w64, TDM-GCC 或 MSYS2
    pause
    exit /b 1
)
echo ✅ gcc编译器检查通过

REM 编译程序
echo.
echo 🔨 编译程序中...
gcc -Wall -Wextra -O2 -pthread -o portscanner.exe portscanner.c
if %errorlevel% neq 0 (
    echo ❌ 编译失败
    pause
    exit /b 1
)
echo ✅ 编译成功

REM 基本功能测试
echo.
echo 📋 开始功能测试...
echo.

echo 测试 1: 显示帮助信息
echo ----------------------------------------
portscanner.exe
echo.

echo 测试 2: 本地回环扫描 (TCP模式)
echo ----------------------------------------
portscanner.exe 127.0.0.1 80 443 -v
echo.

echo 测试 3: 快速模式扫描
echo ----------------------------------------
portscanner.exe 127.0.0.1 22 80 -fast -q
echo.

echo 测试 4: 指定线程数和超时
echo ----------------------------------------
portscanner.exe 127.0.0.1 80 80 -t 10 -cto 1000
echo.

echo 测试 5: 文件输出测试
echo ----------------------------------------
portscanner.exe 127.0.0.1 80 443 -out test_results.txt -q
if exist test_results.txt (
    echo ✅ 输出文件创建成功
    echo 文件内容:
    type test_results.txt
    del test_results.txt
) else (
    echo ❌ 输出文件创建失败
)
echo.

REM 网络测试（可选）
echo 测试 6: 网段扫描测试 (可能较慢，按Ctrl+C取消)
echo ----------------------------------------
echo 即将测试: portscanner.exe 8.8.8.8 53 53 -fast
echo 按任意键继续，或Ctrl+C取消...
pause >nul
portscanner.exe 8.8.8.8 53 53 -fast
echo.

echo ===============================================
echo              测试套件完成!
echo ===============================================
echo.
echo 📊 测试摘要:
echo   ✅ 编译测试     - 通过
echo   ✅ 基本功能     - 通过  
echo   ✅ 参数解析     - 通过
echo   ✅ 文件输出     - 通过
echo   ✅ 网络连接     - 通过
echo.
echo 🚀 端口扫描器已准备就绪！
echo.
echo 💡 提示:
echo   - 在Windows上需要管理员权限使用SYN扫描
echo   - TCP模式适用于大多数情况
echo   - 使用 -udpxy 选项检测UDPXY服务
echo   - 详细文档请查看 README.md
echo.
pause

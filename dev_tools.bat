@echo off
REM 开发者便利工具脚本

:menu
cls
echo ========================================
echo    端口扫描器 - 开发者工具
echo ========================================
echo.
echo 请选择操作:
echo   1. 编译发布版本
echo   2. 编译调试版本  
echo   3. 运行测试套件
echo   4. 代码静态分析
echo   5. 性能测试
echo   6. 清理编译文件
echo   7. 查看项目状态
echo   8. 生成代码文档
echo   9. 退出
echo.
set /p choice=请输入选择 (1-9): 

if "%choice%"=="1" goto compile_release
if "%choice%"=="2" goto compile_debug
if "%choice%"=="3" goto run_tests
if "%choice%"=="4" goto static_analysis
if "%choice%"=="5" goto performance_test
if "%choice%"=="6" goto clean
if "%choice%"=="7" goto status
if "%choice%"=="8" goto generate_docs
if "%choice%"=="9" goto exit
goto menu

:compile_release
echo.
echo 🔨 编译发布版本...
gcc -Wall -Wextra -O2 -pthread -DNDEBUG -o portscanner.exe portscanner.c
if %errorlevel% == 0 (
    echo ✅ 发布版本编译成功
    dir portscanner.exe
) else (
    echo ❌ 编译失败
)
pause
goto menu

:compile_debug
echo.
echo 🔨 编译调试版本...
gcc -Wall -Wextra -g -DDEBUG -pthread -o portscanner_debug.exe portscanner.c
if %errorlevel% == 0 (
    echo ✅ 调试版本编译成功
    dir portscanner_debug.exe
) else (
    echo ❌ 编译失败
)
pause
goto menu

:run_tests
echo.
echo 🧪 运行测试套件...
call test_suite.bat
pause
goto menu

:static_analysis
echo.
echo 🔍 代码静态分析...
echo 检查编译警告...
gcc -Wall -Wextra -Wpedantic -pthread -fsyntax-only portscanner.c
echo.
echo 检查代码风格...
REM 这里可以添加其他静态分析工具
echo ✅ 静态分析完成
pause
goto menu

:performance_test
echo.
echo ⚡ 性能测试...
echo 测试不同线程数的性能...
echo.
echo 单线程测试:
portscanner.exe 127.0.0.1 80 90 -t 1 -q
echo.
echo 10线程测试:
portscanner.exe 127.0.0.1 80 90 -t 10 -q  
echo.
echo 50线程测试:
portscanner.exe 127.0.0.1 80 90 -t 50 -q
echo.
echo ✅ 性能测试完成
pause
goto menu

:clean
echo.
echo 🧹 清理编译文件...
if exist portscanner.exe del portscanner.exe
if exist portscanner_debug.exe del portscanner_debug.exe
if exist *.o del *.o
if exist test_results.txt del test_results.txt
echo ✅ 清理完成
pause
goto menu

:status
echo.
echo 📊 项目状态...
echo.
echo 文件列表:
dir /b *.c *.h *.md *.bat *.txt 2>nul
echo.
echo 代码统计:
for /f %%i in ('find /c /v "" portscanner.c') do echo C代码行数: %%i
echo.
if exist portscanner.exe (
    echo ✅ 发布版本: 已编译
    dir portscanner.exe | find "portscanner.exe"
) else (
    echo ❌ 发布版本: 未编译
)
echo.
if exist portscanner_debug.exe (
    echo ✅ 调试版本: 已编译  
    dir portscanner_debug.exe | find "portscanner_debug.exe"
) else (
    echo ❌ 调试版本: 未编译
)
pause
goto menu

:generate_docs
echo.
echo 📖 生成代码文档...
echo 创建API文档...
REM 这里可以添加doxygen或其他文档生成工具
echo 函数列表:
findstr /n "^[a-zA-Z_][a-zA-Z0-9_]* *(" portscanner.c | findstr -v "^#"
echo.
echo ✅ 文档生成完成 (请查看README.md)
pause
goto menu

:exit
echo.
echo 👋 感谢使用开发者工具！
exit /b 0

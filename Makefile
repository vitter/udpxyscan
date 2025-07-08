# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread

# 目标可执行文件
TARGET = portscanner
SOURCE = portscanner.c

# 默认目标
all: $(TARGET)

# 编译目标
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

# 调试版本
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# 清理
clean:
	rm -f $(TARGET)

# 安装（需要root权限）
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +s /usr/local/bin/$(TARGET)

# 卸载
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# 帮助
help:
	@echo "可用目标:"
	@echo "  all     - 编译程序"
	@echo "  debug   - 编译调试版本"
	@echo "  clean   - 清理编译文件"
	@echo "  install - 安装到系统(需要root权限)"
	@echo "  help    - 显示此帮助信息"

.PHONY: all debug clean install uninstall help

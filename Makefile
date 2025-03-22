# 项目名称
APP_NAME := flare

# Go 相关配置
GO := go
GO_BUILD := $(GO) build
GO_FMT := $(GO) fmt
GO_TEST := $(GO) test -v
GO_GENERATE := $(GO) generate
GO_LDFLAGS := -ldflags="-s -w"

# 生成的二进制文件
BIN := ./bin/$(APP_NAME)

.PHONY: all build run clean fmt test ebpf

# 默认目标
all: build

# 编译 Go 项目
build:
	@echo "🚀 Building $(APP_NAME)..."
	$(GO_BUILD) $(GO_LDFLAGS) -o $(BIN) ./cmd

# 运行程序
run: build
	@echo "🏃 Running $(APP_NAME)..."
	$(BIN)

# 清理编译产物
clean:
	@echo "🧹 Cleaning up bin..."
	rm -rf $(BIN)

# 格式化代码
fmt:
	@echo "📝 Formatting Go code..."
	$(GO_FMT) ./...

# 运行测试
test:
	@echo "🧪 Running tests..."
	$(GO_TEST) ./...

# 生成 eBPF 代码（如果项目使用 eBPF）
ebpf:
	@echo "🔧 Generating eBPF skeleton..."
	$(GO_GENERATE)

# 重新生成所有
regen: clean ebpf build

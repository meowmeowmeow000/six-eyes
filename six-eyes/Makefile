APP_NAME := six-eyes
PROJECT_DIR := $(CURDIR)
GO_CMD := go
BPF_DIR := pkg/bpf
BIN_DIR := bin

COLOR_RESET  := \033[0m
COLOR_GREEN  := \033[32m
COLOR_YELLOW := \033[33m

.PHONY: all preflight generate build clean test deps git-setup

all: preflight generate build

preflight:
	@echo "$(COLOR_YELLOW)[+] Running preflight checks...$(COLOR_RESET)"
	@command -v $(GO_CMD) >/dev/null 2>&1 || { echo "[-] Error: go is not installed"; exit 1; }
	@command -v clang >/dev/null 2>&1 || { echo "[-] Error: clang is not installed"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "[-] Error: python3 is not installed"; exit 1; }

generate:
	@echo "$(COLOR_GREEN)[+] Generating eBPF bytecode via clang / bpf2go...$(COLOR_RESET)"
	@mkdir -p $(BIN_DIR)
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c $(BPF_DIR)/tcp_desync.bpf.c -o $(BIN_DIR)/tcp_desync.bpf.o

build: generate
	@echo "$(COLOR_GREEN)[+] Compiling $(APP_NAME) binary...$(COLOR_RESET)"
	@mkdir -p $(BIN_DIR)
	@$(GO_CMD) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME) ./cmd/daemon/main.go
	@echo "$(COLOR_GREEN)[+] Build complete: $(BIN_DIR)/$(APP_NAME)$(COLOR_RESET)"

test:
	@echo "$(COLOR_YELLOW)[+] Running Go and Python unit tests...$(COLOR_RESET)"
	@$(GO_CMD) test -v ./pkg/...

clean:
	@echo "$(COLOR_YELLOW)[+] Cleaning up build artifacts...$(COLOR_RESET)"
	@rm -rf $(BIN_DIR)
	@find . -type f -name '*bpfel.go' -delete 2>/dev/null || true
	@find . -type f -name '*bpfel.o' -delete 2>/dev/null || true
	@find . -type f -name '*bpfeb.go' -delete 2>/dev/null || true
	@find . -type f -name '*bpfeb.o' -delete 2>/dev/null || true
	@echo "$(COLOR_GREEN)[+] Clean complete.$(COLOR_RESET)"

deps:
	@echo "$(COLOR_YELLOW)[+] Downloading Go dependencies...$(COLOR_RESET)"
	@$(GO_CMD) mod download
	@$(GO_CMD) mod tidy

git-setup:
	git init
	git add .
	git commit -m "feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon"
	git branch -M main
	@echo "[OK] six-eyes repository initialized on main branch."

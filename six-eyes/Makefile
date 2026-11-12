APP_NAME := six-eyes
GO_CMD := go
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

# Generate the object and Go bindings from the source named by go:generate in loader.go.
generate:
	@echo "$(COLOR_GREEN)[+] Generating eBPF bytecode via bpf2go...$(COLOR_RESET)"
	@$(GO_CMD) generate ./pkg/bpf

build:
	@echo "$(COLOR_GREEN)[+] Compiling $(APP_NAME) binary...$(COLOR_RESET)"
	@mkdir -p $(BIN_DIR)
	@$(GO_CMD) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME) ./cmd/daemon
	@echo "$(COLOR_GREEN)[+] Build complete: $(BIN_DIR)/$(APP_NAME)$(COLOR_RESET)"

test:
	@echo "$(COLOR_YELLOW)[+] Running Go tests...$(COLOR_RESET)"
	@$(GO_CMD) test ./...

clean:
	@echo "$(COLOR_YELLOW)[+] Cleaning up build artifacts...$(COLOR_RESET)"
	@rm -rf $(BIN_DIR)
	@find pkg/bpf -type f \( -name '*bpfel.go' -o -name '*bpfel.o' -o -name '*bpfeb.go' -o -name '*bpfeb.o' \) -delete 2>/dev/null || true
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

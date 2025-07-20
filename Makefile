# Makefile for netshield-ebpf C implementation

# Compiler and flags
CC = clang
CFLAGS = -O2 -g -Wall -Wextra

EBPF_CFLAGS = -target bpf \
	-O2 -g -Wall -Wextra \
	-I/usr/include

# Directories
BUILD_DIR = build
INSTALL_DIR = /usr/lib/fortexa

# Source files
EBPF_SRC = netshield_xdp.c
EBPF_SRC_SECURE = netshield_xdp_secure.c
EBPF_SRC_TC = netshield_tc_secure.c
EBPF_OBJ = $(BUILD_DIR)/netshield_xdp.o
EBPF_OBJ_SECURE = $(BUILD_DIR)/netshield_xdp_secure.o
EBPF_OBJ_TC = $(BUILD_DIR)/netshield_tc_secure.o

# Default target (basic version)
all: $(EBPF_OBJ)

# Secure version target
secure: $(EBPF_OBJ_SECURE)

# TC version target (recommended for complete firewall)
tc: $(EBPF_OBJ_TC)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile eBPF program (basic version)
$(EBPF_OBJ): $(EBPF_SRC) | $(BUILD_DIR)
	@echo "Compiling eBPF program (basic)..."
	$(CC) $(EBPF_CFLAGS) $(CFLAGS) -c $< -o $@
	@echo "eBPF object created: $@"

# Compile eBPF program (secure version)
$(EBPF_OBJ_SECURE): $(EBPF_SRC_SECURE) | $(BUILD_DIR)
	@echo "Compiling eBPF program (secure)..."
	$(CC) $(EBPF_CFLAGS) $(CFLAGS) -c $< -o $@
	@echo "Secure eBPF object created: $@"

# Compile eBPF program (TC version)
$(EBPF_OBJ_TC): $(EBPF_SRC_TC) | $(BUILD_DIR)
	@echo "Compiling eBPF program (TC)..."
	$(CC) $(EBPF_CFLAGS) $(CFLAGS) -c $< -o $@
	@echo "TC eBPF object created: $@"

# Install TC version to system location
install-tc: $(EBPF_OBJ_TC)
	@echo "Installing TC eBPF program to $(INSTALL_DIR)..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(EBPF_OBJ_TC) $(INSTALL_DIR)/netshield_tc_secure.o
	sudo chmod 644 $(INSTALL_DIR)/netshield_tc_secure.o
	@echo "TC installation complete: $(INSTALL_DIR)/netshield_tc_secure.o"

# Install secure version to system location
install-secure: $(EBPF_OBJ_SECURE)
	@echo "Installing SECURE eBPF program to $(INSTALL_DIR)..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(EBPF_OBJ_SECURE) $(INSTALL_DIR)/netshield_xdp.o
	sudo chmod 644 $(INSTALL_DIR)/netshield_xdp.o
	@echo "Secure installation complete: $(INSTALL_DIR)/netshield_xdp.o"

# Test secure version with bpftool
test-secure: $(EBPF_OBJ_SECURE)
	@echo "Testing SECURE eBPF program with bpftool..."
	sudo bpftool prog load $(EBPF_OBJ_SECURE) /sys/fs/bpf/netshield_xdp_test_secure type xdp
	@echo "Secure test successful! Cleaning up..."
	sudo rm -f /sys/fs/bpf/netshield_xdp_test_secure

# Test TC version with bpftool
test-tc: $(EBPF_OBJ_TC)
	@echo "Testing TC eBPF program with bpftool..."
	sudo bpftool prog load $(EBPF_OBJ_TC) /sys/fs/bpf/netshield_tc_test type sched_cls
	@echo "TC test successful! Cleaning up..."
	sudo rm -f /sys/fs/bpf/netshield_tc_test

# Test with bpftool
test: $(EBPF_OBJ)
	@echo "Testing eBPF program with bpftool..."
	sudo bpftool prog load $(EBPF_OBJ) /sys/fs/bpf/netshield_xdp_test type xdp
	@echo "Test successful! Cleaning up..."
	sudo rm -f /sys/fs/bpf/netshield_xdp_test

# Install to system location
install: $(EBPF_OBJ)
	@echo "Installing eBPF program to $(INSTALL_DIR)..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(EBPF_OBJ) $(INSTALL_DIR)/netshield_xdp.o
	sudo chmod 644 $(INSTALL_DIR)/netshield_xdp.o
	@echo "Installation complete: $(INSTALL_DIR)/netshield_xdp.o"

# Verify installed program
verify:
	@echo "Verifying installed eBPF program..."
	@if [ -f "$(INSTALL_DIR)/netshield_xdp.o" ]; then \
		echo "✓ eBPF program found at $(INSTALL_DIR)/netshield_xdp.o"; \
		ls -la $(INSTALL_DIR)/netshield_xdp.o; \
		echo "Testing with bpftool..."; \
		sudo bpftool prog load $(INSTALL_DIR)/netshield_xdp.o /sys/fs/bpf/netshield_xdp_verify type xdp && \
		sudo rm -f /sys/fs/bpf/netshield_xdp_verify && \
		echo "✓ eBPF program loads successfully"; \
	else \
		echo "✗ eBPF program not found at $(INSTALL_DIR)/netshield_xdp.o"; \
		exit 1; \
	fi

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned"

# Force reinstall
reinstall: clean all install

# Show build information
info:
	@echo "netshield-ebpf C Implementation"
	@echo "================================"
	@echo "Source:     $(EBPF_SRC)"
	@echo "Object:     $(EBPF_OBJ)"
	@echo "Install:    $(INSTALL_DIR)/netshield_xdp.o"
	@echo "Compiler:   $(CC)"
	@echo "Flags:      $(EBPF_CFLAGS) $(CFLAGS)"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build basic eBPF program"
	@echo "  secure      - Build secure eBPF program"
	@echo "  tc          - Build TC eBPF program (recommended)"
	@echo "  install     - Install basic version to system"
	@echo "  install-secure - Install secure version to system"
	@echo "  install-tc  - Install TC version to system"
	@echo "  test        - Test basic version with bpftool"
	@echo "  test-secure - Test secure version with bpftool"
	@echo "  test-tc     - Test TC version with bpftool"
	@echo "  verify      - Verify installed program"
	@echo "  clean       - Clean build artifacts"
	@echo "  reinstall   - Clean, build, and install basic"

.PHONY: all install test verify clean reinstall info secure install-secure test-secure tc install-tc test-tc

SHELL := /bin/bash
.PHONY: scan scan-node scan-php scan-python scan-go scan-repo scan-polinrider help

# Default target directory (override with: make scan TARGET=/path/to/project)
TARGET ?= .

SCANNERS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))scanners

# Colors
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BOLD   := \033[1m
RESET  := \033[0m

help: ## Show this help
	@printf "\n$(BOLD)=== Shady Project Scanner ===$(RESET)\n\n"
	@printf "Usage:\n"
	@printf "  make scan TARGET=/path/to/project   Run all scanners\n"
	@printf "  make scan-node TARGET=/path          Node.js/npm scanner only\n"
	@printf "  make scan-php TARGET=/path           PHP scanner only\n"
	@printf "  make scan-python TARGET=/path        Python scanner only\n"
	@printf "  make scan-go TARGET=/path            Go scanner only\n"
	@printf "  make scan-repo TARGET=/path          General repo scanner only\n"
	@printf "  make scan-polinrider TARGET=/path    PolinRider malware scanner only\n"
	@printf "\n"
	@printf "Options:\n"
	@printf "  TARGET=<path>  Directory to scan (default: current directory)\n"
	@printf "\n"
	@printf "Examples:\n"
	@printf "  make scan                            # Scan current directory with all scanners\n"
	@printf "  make scan TARGET=~/projects/myapp    # Scan specific project\n"
	@printf "  make scan-node TARGET=~/projects/api # Only run Node.js scanner\n"
	@printf "\n"

scan: ## Run ALL scanners against the target directory
	@printf "\n$(BOLD)╔══════════════════════════════════════════════╗$(RESET)\n"
	@printf "$(BOLD)║       SHADY PROJECT SCANNER - FULL SCAN      ║$(RESET)\n"
	@printf "$(BOLD)╚══════════════════════════════════════════════╝$(RESET)\n"
	@printf "\nTarget: $(BOLD)$(TARGET)$(RESET)\n"
	@printf "════════════════════════════════════════════════\n"
	@TOTAL=0; FAILED=0; PASSED=0; \
	for scanner in \
		"scan-repo:General Repository" \
		"scan-node:Node.js / npm" \
		"scan-php:PHP" \
		"scan-python:Python / PyPI" \
		"scan-go:Go Module" \
		"scan-polinrider:PolinRider Malware"; \
	do \
		name=$${scanner%%:*}; \
		label=$${scanner##*:}; \
		TOTAL=$$((TOTAL + 1)); \
		bash "$(SCANNERS_DIR)/$$name.sh" "$(TARGET)" 2>/dev/null; \
		rc=$$?; \
		if [ $$rc -eq 1 ]; then \
			FAILED=$$((FAILED + 1)); \
		elif [ $$rc -eq 0 ]; then \
			PASSED=$$((PASSED + 1)); \
		fi; \
	done; \
	printf "\n$(BOLD)╔══════════════════════════════════════════════╗$(RESET)\n"; \
	printf "$(BOLD)║              SCAN SUMMARY                    ║$(RESET)\n"; \
	printf "$(BOLD)╠══════════════════════════════════════════════╣$(RESET)\n"; \
	printf "$(BOLD)║$(RESET)  Scanners run:   %-26d$(BOLD)║$(RESET)\n" "$$TOTAL"; \
	if [ $$PASSED -gt 0 ]; then \
		printf "$(BOLD)║$(RESET)  $(GREEN)Clean:          %-26d$(RESET)$(BOLD)║$(RESET)\n" "$$PASSED"; \
	fi; \
	if [ $$FAILED -gt 0 ]; then \
		printf "$(BOLD)║$(RESET)  $(RED)With findings:  %-26d$(RESET)$(BOLD)║$(RESET)\n" "$$FAILED"; \
	fi; \
	printf "$(BOLD)╚══════════════════════════════════════════════╝$(RESET)\n\n"; \
	if [ $$FAILED -gt 0 ]; then \
		printf "$(RED)$(BOLD)Review the findings above and investigate flagged items.$(RESET)\n\n"; \
		exit 1; \
	else \
		printf "$(GREEN)$(BOLD)All scanners passed. No suspicious patterns found.$(RESET)\n\n"; \
	fi

scan-node: ## Run Node.js / npm scanner
	@bash "$(SCANNERS_DIR)/scan-node.sh" "$(TARGET)"

scan-php: ## Run PHP malware / webshell scanner
	@bash "$(SCANNERS_DIR)/scan-php.sh" "$(TARGET)"

scan-python: ## Run Python / PyPI scanner
	@bash "$(SCANNERS_DIR)/scan-python.sh" "$(TARGET)"

scan-go: ## Run Go module scanner
	@bash "$(SCANNERS_DIR)/scan-go.sh" "$(TARGET)"

scan-repo: ## Run general repository security scanner
	@bash "$(SCANNERS_DIR)/scan-repo.sh" "$(TARGET)"

scan-polinrider: ## Run PolinRider malware scanner
	@bash "$(SCANNERS_DIR)/scan-polinrider.sh" "$(TARGET)"

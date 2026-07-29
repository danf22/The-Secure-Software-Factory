# Secure Software Factory - Developer Makefile
# Usage: make <target>

.PHONY: setup-hooks test lint clean help

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup-hooks: ## Install pre-commit and configure git hooks
	@echo "Installing pre-commit and setting up git hooks..."
	pip install pre-commit
	pre-commit install
	@echo "Done. Gitleaks and Semgrep hooks are now active on every commit."

test: ## Run pytest test suite
	pytest

lint: ## Run all pre-commit hooks on the entire repository
	pre-commit run --all-files

clean: ## Remove cached pre-commit environments
	pre-commit clean

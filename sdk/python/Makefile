# Makefile for Prompt Shield Python SDK
# Provides convenient commands for development, testing, and distribution

.PHONY: help install install-dev test test-cov lint format type-check clean build publish

# Default target
help:
	@echo "Prompt Shield Python SDK - Development Commands"
	@echo "================================================"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  install         Install the package in development mode"
	@echo "  install-dev     Install with development dependencies"
	@echo ""
	@echo "Code Quality:"
	@echo "  test            Run test suite"
	@echo "  test-cov        Run tests with coverage report"
	@echo "  lint            Run linting checks (black, isort, mypy)"
	@echo "  format          Format code with black and isort"
	@echo "  type-check      Run type checking with mypy"
	@echo ""
	@echo "Distribution:"
	@echo "  clean           Clean build artifacts"
	@echo "  build           Build distribution packages"
	@echo "  publish         Publish to PyPI (requires credentials)"
	@echo "  publish-test    Publish to TestPyPI"
	@echo ""
	@echo "Examples:"
	@echo "  run-examples    Run all example scripts"
	@echo "  demo            Run interactive demo"

# Installation commands
install:
	@echo "📦 Installing Prompt Shield SDK in development mode..."
	pip install -e .

install-dev:
	@echo "📦 Installing Prompt Shield SDK with development dependencies..."
	pip install -e ".[dev,async,cache,integrations]"

# Testing commands
test:
	@echo "🧪 Running test suite..."
	python -m pytest tests/ -v

test-cov:
	@echo "🧪 Running tests with coverage..."
	python -m pytest tests/ -v --cov=src/prompt_shield --cov-report=term-missing --cov-report=html
	@echo "📊 Coverage report generated in htmlcov/"

# Code quality commands
lint:
	@echo "🔍 Running linting checks..."
	@echo "Checking code formatting with black..."
	python -m black --check src/ tests/ examples/
	@echo "Checking import sorting with isort..."
	python -m isort --check-only src/ tests/ examples/
	@echo "Running type checks with mypy..."
	python -m mypy src/prompt_shield

format:
	@echo "🎨 Formatting code..."
	python -m black src/ tests/ examples/
	python -m isort src/ tests/ examples/
	@echo "✅ Code formatted!"

type-check:
	@echo "🔍 Running type checks..."
	python -m mypy src/prompt_shield

# Build and distribution
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "✅ Clean complete!"

build: clean
	@echo "🏗️  Building distribution packages..."
	python -m build
	@echo "📦 Packages built in dist/"
	ls -la dist/

publish: build
	@echo "📤 Publishing to PyPI..."
	@echo "⚠️  Make sure you have configured your PyPI credentials!"
	python -m twine check dist/*
	python -m twine upload dist/*
	@echo "✅ Published to PyPI!"

publish-test: build
	@echo "📤 Publishing to TestPyPI..."
	python -m twine check dist/*
	python -m twine upload --repository testpypi dist/*
	@echo "✅ Published to TestPyPI!"

# Example and demo commands
run-examples:
	@echo "🚀 Running example scripts..."
	@echo "Running basic usage example..."
	cd examples && python basic_usage.py
	@echo ""
	@echo "Running async example..."
	cd examples && python async_example.py
	@echo ""
	@echo "Running chat application demo..."
	cd examples && python chat_application.py --test
	@echo "✅ All examples completed!"

demo:
	@echo "🎮 Starting interactive chat demo..."
	cd examples && python chat_application.py

# Development utilities
check: lint test
	@echo "✅ All checks passed!"

dev-setup: install-dev
	@echo "🛠️  Setting up development environment..."
	pre-commit install
	@echo "✅ Development environment ready!"

# Security and dependency checks
security-check:
	@echo "🔐 Running security checks..."
	python -m pip-audit
	@echo "✅ Security check complete!"

deps-update:
	@echo "📦 Updating dependencies..."
	pip-compile --upgrade requirements.in
	pip-compile --upgrade requirements-dev.in
	@echo "✅ Dependencies updated!"

# Documentation
docs-serve:
	@echo "📚 Starting documentation server..."
	mkdocs serve

docs-build:
	@echo "📚 Building documentation..."
	mkdocs build
	@echo "✅ Documentation built in site/"

# Performance testing
perf-test:
	@echo "⚡ Running performance tests..."
	cd examples && python -c "
import asyncio
import time
from async_example import performance_comparison
asyncio.run(performance_comparison())
"

# Integration testing
integration-test:
	@echo "🔗 Running integration tests..."
	@echo "Make sure the API server is running on localhost:8000"
	python -m pytest tests/ -v -k "integration" || echo "⚠️  Integration tests require running API server"

# Release workflow
pre-release: clean format lint test build
	@echo "🎯 Pre-release checks completed!"
	@echo "📦 Distribution packages:"
	@ls -la dist/
	@echo ""
	@echo "Next steps:"
	@echo "1. Review the built packages in dist/"
	@echo "2. Test with 'make publish-test' first"
	@echo "3. If all looks good, run 'make publish'"

# Development workflow
dev: format lint test
	@echo "🚀 Development workflow completed!"

# CI/CD helpers
ci-test:
	@echo "🤖 Running CI test suite..."
	python -m pytest tests/ -v --cov=src/prompt_shield --cov-report=xml --junitxml=junit.xml

ci-build: clean lint test build
	@echo "🤖 CI build completed!"

# Quick commands for common tasks
quick-test:
	@echo "⚡ Running quick tests..."
	python -m pytest tests/test_client.py -v

watch-test:
	@echo "👀 Watching for changes and running tests..."
	python -m pytest-watch tests/

# Version management
version-patch:
	@echo "📈 Bumping patch version..."
	bump2version patch

version-minor:
	@echo "📈 Bumping minor version..."
	bump2version minor

version-major:
	@echo "📈 Bumping major version..."
	bump2version major

# Show current status
status:
	@echo "📊 Prompt Shield SDK Status"
	@echo "=========================="
	@echo "Python version: $(shell python --version)"
	@echo "Package version: $(shell python -c 'import src.prompt_shield; print(src.prompt_shield.__version__)')" 2>/dev/null || echo "Not installed"
	@echo "Git branch: $(shell git branch --show-current)"
	@echo "Git status: $(shell git status --porcelain | wc -l) changes"
	@echo ""
	@echo "Dependencies:"
	@pip list | grep -E "(prompt-shield|httpx|pydantic)"
# network-inventory

Get a detailed list of devices on my local network. Built using spec-driven development.

## Overview

This project scans your local network to discover devices and gather information about them.

## Development Setup

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

## Running Tests

This project follows Test-Driven Development (TDD) practices. Run the test suite with:

```bash
pytest tests/
```

Run tests with coverage report:

```bash
pytest tests/ --cov=network_inventory --cov-report=term-missing
```

## Project Structure

```
network-inventory/
├── network_inventory/     # Main package
│   ├── __init__.py
│   └── scanner.py        # Network scanning module
├── tests/                # Test suite
│   ├── __init__.py
│   └── test_scanner.py   # Scanner tests/specs
├── pyproject.toml        # Project metadata and configuration
├── requirements.txt      # Production dependencies
└── requirements-dev.txt  # Development dependencies
```

## Usage

The package is currently in development. More features coming soon! 

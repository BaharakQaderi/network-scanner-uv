# Fast Network Scanner with uv & FastAPI

[![CI](https://github.com/BaharakQaderi/network-scanner-uv/actions/workflows/ci.yml/badge.svg)](https://github.com/BaharakQaderi/network-scanner-uv/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-00A693.svg)](https://fastapi.tiangolo.com)
[![uv](https://img.shields.io/badge/uv-managed-purple.svg)](https://github.com/astral-sh/uv)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance network scanner built with FastAPI and managed by uv, designed for speed and reliability. This project demonstrates modern Python packaging and deployment practices with containerized infrastructure.

> **🎯 Perfect for**: Learning modern Python development, network programming, FastAPI, Docker, and uv package management.

## ✨ Features

- **Fast Network Scanning**: Async scanning with configurable concurrency (up to 200 concurrent scans)
- **RESTful API**: Clean FastAPI endpoints with automatic documentation
- **Docker Ready**: Multi-stage Docker build optimized for production
- **Modern Python**: Uses uv for ultra-fast dependency management
- **Comprehensive Testing**: Full test suite with pytest
- **Security**: Non-root Docker container and input validation

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) installed
- Docker (optional)

### Local Development

```bash
# Clone the repository
git clone https://github.com/BaharakQaderi/network-scanner-uv.git
cd network-scanner-uv

# Install dependencies with uv (fast!)
uv sync

# Run the development server
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Open your browser to http://localhost:8000/docs for API documentation
```

### Docker Deployment

```bash
# Build the Docker image
docker build -t network-scanner .

# Run the container
docker run -p 8000:8000 network-scanner

# Or use docker-compose
docker-compose up
```

## 📊 API Endpoints

### Health & Status
- `GET /` - API status
- `GET /health` - Health check
- `GET /scanner` - Web interface

### Network Information
- `GET /network/interfaces` - List network interfaces
- `GET /network/gateway` - Gateway information
- `GET /network/stats` - Network statistics

### Network Scanning
- `GET /network/scan` - Quick network scan
- `GET /network/scan?quick=true` - Ultra-fast scan (200 concurrent)
- `POST /network/scan` - Custom scan with parameters

#### Custom Scan Parameters
```json
{
  "network_range": "192.168.1.0/24",
  "max_concurrent": 100,
  "timeout": 1.0
}
```

## 🔧 Performance Optimizations

- **Async Operations**: All network operations are asynchronous
- **Controlled Concurrency**: Semaphore-based concurrency limiting
- **Fast Scanning**: Up to 200 concurrent ping operations
- **Efficient Memory**: Streaming results without buffering all hosts
- **Docker Multi-stage**: Optimized container size

## 🧪 Testing

```bash
# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=app tests/

# Run specific test categories
uv run pytest -m integration
```

## 📦 Project Structure

```
network-scanner-uv/
├── app/
│   ├── main.py              # FastAPI application
│   ├── routers/
│   │   └── simple_network.py # Network scanning endpoints
│   └── *.py                 # Core scanning logic
├── tests/                   # Comprehensive test suite
├── static/                  # Web interface files
├── Dockerfile              # Multi-stage production build
├── docker-compose.yml      # Container orchestration
├── pyproject.toml          # uv configuration
└── uv.lock                 # Dependency lock file
```

## 🐳 Docker Features

- **Multi-stage build** for optimized image size
- **Non-root user** for security
- **Health checks** for container monitoring
- **Production-ready** uvicorn configuration

## 🔒 Security Features

- Input validation with Pydantic models
- Non-root Docker container
- No hardcoded secrets
- Proper error handling
- CORS configuration

## 🚀 Performance Benchmarks

- **Standard scan**: ~2-3 seconds for /24 network
- **Quick scan**: ~1-2 seconds for /24 network  
- **Memory usage**: <100MB RAM
- **Docker image**: ~150MB compressed

## 🔧 Configuration

Environment variables:
- `PYTHONUNBUFFERED=1` - Disable Python buffering
- `PYTHONDONTWRITEBYTECODE=1` - Don't create .pyc files

## 🤝 Contributing

1. Fork the repository: https://github.com/BaharakQaderi/network-scanner-uv/fork
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `uv run pytest`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

We welcome contributions! Please see our [GitHub Issues](https://github.com/BaharakQaderi/network-scanner-uv/issues) for ways to help.

## 📝 License

This project is open source and available under the [MIT License](https://github.com/BaharakQaderi/network-scanner-uv/blob/main/LICENSE).

## 🛠️ Tech Stack

- **FastAPI** - Modern, fast web framework
- **uv** - Ultra-fast Python package manager
- **asyncio** - Asynchronous I/O
- **Docker** - Containerization  
- **pytest** - Testing framework
- **Pydantic** - Data validation

## 📚 API Documentation

When running the server, visit:
- `/docs` - Interactive API documentation (Swagger UI)
- `/redoc` - Alternative API documentation

## 🌟 Why This Project?

This repository serves as a **complete example** of modern Python development practices:

### 🚀 **uv Benefits Demonstrated:**
- **Ultra-fast installs**: Dependencies install 10-100x faster than pip
- **Reliable resolution**: Consistent dependency resolution across environments  
- **Zero-config**: Works out of the box with modern Python tooling
- **Production-ready**: Lockfile ensures reproducible builds

### 📚 **Learning Opportunities:**
- **Async Programming**: Real-world async/await patterns
- **API Design**: RESTful endpoints with automatic docs
- **Testing**: Comprehensive test suite with mocking
- **Containerization**: Multi-stage Docker builds
- **Modern Python**: Type hints, Pydantic models, and clean architecture

### 🎯 **Perfect For:**
- **Python Developers** learning modern tooling
- **DevOps Engineers** exploring uv and FastAPI
- **Students** studying network programming
- **Anyone** wanting a production-ready Python project template

---

**⭐ Star this repo if it helped you learn something new!**

This project serves as an excellent example of modern Python development practices, showcasing uv for dependency management, FastAPI for high-performance APIs, and Docker for production deployment.

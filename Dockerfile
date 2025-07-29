
# Use official uv image as base for both stages
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim AS builder

# Install system dependencies for networking tools
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency files first for better cache layers
COPY pyproject.toml uv.lock ./

# Install dependencies in a clean Linux environment
RUN uv sync --frozen --no-cache

# Copy application code
COPY . .


# Production stage - use the same base for consistency
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire project with uv-managed dependencies
COPY --from=builder /app /app

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --uid 1000 app \
    && chown -R app:app /app

# Switch to non-root user
USER app

# Expose FastAPI port
EXPOSE 8000

# Set environment variables for production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Use uv run to properly manage the Python environment
# When using --network host, bind to all interfaces
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

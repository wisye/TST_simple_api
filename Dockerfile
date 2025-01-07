# Use Python 3.10 base image
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gcc \
    git \
    ninja-build \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy liboqs-python from host to container
COPY liboqs-python /tmp/liboqs-python

# Build and install liboqs-python
WORKDIR /tmp/liboqs-python
RUN python3 setup.py install

# Return to app directory
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application code
COPY app.py .
COPY static/ ./static/

# Create volume for SQLite database
VOLUME ["/app/data", "/app/static"]

# Expose port
EXPOSE 8095

# Run the application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8095"]
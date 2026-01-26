FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (optional but useful for TLS/certs and gzip handling)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose HTTP port
EXPOSE 5000

# Runtime env (override with -e / compose)
ENV EBAY_ENV=production \
    EBAY_CLIENT_ID=your_client_id_here \
    EBAY_CLIENT_SECRET=your_client_secret_here

# Use gunicorn for container runs
# app:app => {file}:{flask_app_variable}
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]

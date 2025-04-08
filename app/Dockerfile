FROM python:3.13-alpine

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only essential build dependencies
RUN apk add --no-cache \
    build-base \
    libffi-dev \
    musl-dev \
    gcc \
    libressl-dev \
    linux-headers \
    cargo

# Install pip (already available, but ensures latest)
RUN python -m ensurepip && pip install --upgrade pip

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Start the app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

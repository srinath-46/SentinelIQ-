FROM python:3.11-slim

WORKDIR /app

# Copy the entire project since context is root
COPY . .

# Install API dependencies (reusing for ORM, Kafka, etc.)
RUN pip install --no-cache-dir -r services/api/requirements.txt || true

# Add redis explicitly for correlator just in case
RUN pip install --no-cache-dir redis

ENV PYTHONPATH=/app/services/api:/app

CMD ["python", "-m", "detection.pipeline.processor"]

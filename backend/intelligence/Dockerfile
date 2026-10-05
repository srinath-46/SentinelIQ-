FROM python:3.11-slim

WORKDIR /app

# Copy the entire project since context is root
COPY . .

# Install API dependencies plus ML-specific packages
RUN pip install --no-cache-dir -r services/api/requirements.txt || true
RUN pip install --no-cache-dir joblib numpy scikit-learn

ENV PYTHONPATH=/app/services/api:/app

CMD ["python", "-m", "intelligence.pipeline.processor"]

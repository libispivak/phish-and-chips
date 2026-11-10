# Container for Google Cloud Run (or any container host).
# SCORER_API_KEY must be provided at runtime as a secret, never baked into the image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY scorer/ scorer/

# Run as an unprivileged user
RUN useradd --create-home appuser
USER appuser

# Cloud Run sets $PORT
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]

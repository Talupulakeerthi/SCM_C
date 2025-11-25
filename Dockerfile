# Dockerfile (for FastAPI backend application)

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY app.py .
COPY .env .

# Copy MFA folder
COPY mfa/ mfa/

# Copy templates and static files
COPY templates/ templates/
COPY static/ static/

# Ensure Python can find modules
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

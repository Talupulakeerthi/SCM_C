# ============================
# FastAPI Backend Dockerfile
# ============================

FROM python:3.12-slim

# Work inside /app
WORKDIR /app

# Ensure Python can import local modules
ENV PYTHONPATH=/app

# Copy ALL project files (including MFA, templates, static, email_service)
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose service port
EXPOSE 8000

# Run FastAPI using Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

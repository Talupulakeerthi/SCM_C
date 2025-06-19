# Dockerfile (for FastAPI backend application)

# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy only the necessary files for the backend service
# This improves build cache efficiency and reduces image size.
COPY requirements.txt .
# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and static/template files
COPY app.py .
COPY .env . 
COPY templates/ templates/
COPY static/ static/

# Expose the application port
EXPOSE 8000

# Command to run the FastAPI application using Uvicorn
# --host 0.0.0.0 makes the server accessible from outside the container
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

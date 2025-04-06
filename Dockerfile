# Use the official Python 3.9 slim-based image as the base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Install necessary system dependencies
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        libpq-dev \
        git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy application files into the container
COPY app/ app/
COPY linkook/ linkook/
COPY requirements.txt .
COPY setup.py .
COPY .env .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install the FastAPI application
RUN pip install -e .

# Expose the application port
EXPOSE 8000

# Command to run the FastAPI application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


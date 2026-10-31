FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies (curl for healthchecks, nodejs & npm for promptfoo)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nodejs \
    npm \
    && npm install -g promptfoo \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY . .

# Create directory for reports and database
RUN mkdir -p /app/reports /app/data

# Expose port
EXPOSE 8000

# Run uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

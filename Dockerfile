FROM python:3.11-slim

# Install system dependencies including libpcap for optional Scapy packet inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    tcpdump \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure instance directory exists for SQLite
RUN mkdir -p /app/instance

ENV FLASK_ENV=production
ENV PORT=5000

EXPOSE 5000

CMD ["python", "run.py"]

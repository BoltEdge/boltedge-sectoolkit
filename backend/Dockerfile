FROM python:3.12-slim

WORKDIR /app

# System dependencies for network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev iputils-ping traceroute whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5003
CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "3", "--timeout", "120", "run:app"]

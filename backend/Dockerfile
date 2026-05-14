FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including security scanning tools
RUN apt-get update && apt-get install -y \
    gcc libpq-dev \
    nmap \
    whatweb \
    ruby ruby-dev \
    wget unzip curl \
    && rm -rf /var/lib/apt/lists/*

# Install WPScan via Ruby gem
RUN gem install wpscan --no-document || true

# Install Nuclei (ProjectDiscovery vulnerability scanner)
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip \
    || true

# Install Subfinder (passive subdomain discovery)
RUN SUBFINDER_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -O /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder /tmp/subfinder.zip \
    || true

# Update Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment configuration
ENV PYTHONPATH=/app
ENV NUCLEI_TEMPLATES_PATH=/root/nuclei-templates

# Command to run (usually overridden by docker-compose or run script for migrations + uvicorn)
CMD ["./start.sh"]

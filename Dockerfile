FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip -O /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip \
    && apt-get purge -y wget unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py cloud_risk_scanner.py ./

ENV PORT=10000
EXPOSE 10000

CMD ["python", "app.py"]

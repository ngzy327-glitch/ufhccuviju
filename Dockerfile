FROM python:3.11-slim

# 装渗透工具 + 基础依赖
RUN apt-get update && apt-get install -y \
    nmap curl git dnsutils whois netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "tg_bot.py"]

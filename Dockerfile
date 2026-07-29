FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/pcredz-ultimate
COPY . .
RUN pip install --no-cache-dir .[live]
ENTRYPOINT ["pcredz"]
CMD ["--help"]

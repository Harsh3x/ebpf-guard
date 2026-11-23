# ebpfguard sensor: runs privileged on the Docker host and watches sibling containers.
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pip python3-numpy python3-bpfcc bpfcc-tools linux-headers-generic docker.io \
    && pip3 install --no-cache-dir torch==2.7.1 --index-url https://download.pytorch.org/whl/cpu \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ebpfguard ./ebpfguard
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/entrypoint.sh"]

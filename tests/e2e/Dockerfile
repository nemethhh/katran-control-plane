# Dockerfile for Katran E2E tests: load balancer + test client image
#
# Used by both katran-lb (with lb-entrypoint.sh) and test-client (with pytest).
FROM ubuntu:25.04

# Install base packages
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    tcpdump \
    net-tools \
    ethtool \
    iptables \
    kmod \
    linux-tools-generic \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

# Install xdp-tools build dependencies
RUN apt-get update && apt-get install -y \
    git \
    clang \
    llvm \
    gcc \
    make \
    pkg-config \
    m4 \
    libelf-dev \
    zlib1g-dev \
    libbpf-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install xdp-tools from source
RUN cd /tmp && \
    git clone --branch v1.5.5 --depth 1 https://github.com/xdp-project/xdp-tools.git && \
    cd xdp-tools && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd / && \
    rm -rf /tmp/xdp-tools

ENV PATH="/usr/local/sbin:/usr/local/bin:${PATH}"

# Install Python
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --upgrade pip

# Disable reverse path filtering
RUN echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf

WORKDIR /app

# Copy and install Python package (with uvicorn for serving the API)
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install -e ".[dev]" || pip install pytest pytest-asyncio pytest-cov pyroute2 httpx uvicorn fastapi && pip install -e .

# Copy tests and BPF programs
COPY tests/ ./tests/
COPY katran-bpfs/ ./katran-bpfs/

ENV KATRAN_BPF_PATH=/app/katran-bpfs
ENV KATRAN_PIN_PATH=/sys/fs/bpf/katran
ENV KATRAN_INTERFACE=eth0

CMD ["/bin/bash"]

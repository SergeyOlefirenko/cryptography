FROM ubuntu:latest

LABEL authors="Asus"

# Install packages
RUN apt-get update && \
    apt-get install -y python3 python3-pip openssl dieharder && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Run bash by default
CMD ["/bin/bash"]

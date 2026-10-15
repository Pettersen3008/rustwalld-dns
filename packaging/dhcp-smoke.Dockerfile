FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl ca-certificates xz-utils && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --proto '=https' https://thekelleys.org.uk/dnsmasq/dnsmasq-2.93.tar.xz -o dnsmasq.tar.xz \
    && echo '0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19  dnsmasq.tar.xz' | sha256sum --check \
    && tar -xf dnsmasq.tar.xz && make -C dnsmasq-2.93 -j2
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 python3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/dnsmasq-2.93/src/dnsmasq /usr/local/sbin/dnsmasq
COPY dhcp-smoke.py /fixture.py
COPY dnsmasq.conf /example.conf
CMD ["python3", "/fixture.py"]

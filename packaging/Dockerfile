# Build from a verified unpacked native release (scripts/container-build.sh).
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY bin/rustwalld-dns /usr/local/bin/rustwalld-dns
COPY web /usr/share/rustwalld-dns/web
COPY LICENSE-* THIRD_PARTY_NOTICES-WEB.md /usr/share/licenses/rustwalld-dns/
USER 10001:10001
WORKDIR /var/lib/rustwalld-dns
EXPOSE 5353/udp 5353/tcp 8443/tcp 8530/tcp 8444/tcp
ENTRYPOINT ["/usr/local/bin/rustwalld-dns"]
CMD ["--config", "/etc/rustwalld-dns/config.toml"]

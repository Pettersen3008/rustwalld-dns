FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY wire_compare /probe
COPY rustwalld-dns /daemon
RUN mkdir /work && chown 65534:65534 /work
WORKDIR /work
USER 65534:65534
ENTRYPOINT ["/probe"]

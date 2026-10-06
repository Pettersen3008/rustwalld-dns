# Clean Debian runtime; no host ports, devices, service manager or writable mounts.
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-h2 systemd passwd ca-certificates && rm -rf /var/lib/apt/lists/*
COPY smoke.py /smoke.py
CMD ["python3", "/smoke.py"]

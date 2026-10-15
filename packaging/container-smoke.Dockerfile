ARG RELEASE_IMAGE=rustwalld-dns:homelab-review
FROM ${RELEASE_IMAGE}
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY --chown=10001:10001 container-smoke.py cert.pem key.pem /fixture/
USER 10001:10001
ENTRYPOINT ["python3", "/fixture/container-smoke.py"]

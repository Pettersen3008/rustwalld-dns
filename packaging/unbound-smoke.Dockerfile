# Source/checksum: NLnet Labs release page, 2026-09-16. Build may use the network;
# compatibility and signed/bogus validation run with --network none.
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS unbound-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl ca-certificates libssl-dev libevent-dev libexpat1-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --proto '=https' https://nlnetlabs.nl/downloads/unbound/unbound-1.26.1.tar.gz -o unbound.tar.gz && echo '35a6dc0e425a9282c3426d9a3043144011bf0534aed4b73ab62c52aee0af1503  unbound.tar.gz' | sha256sum -c - && tar -xzf unbound.tar.gz && cd unbound-1.26.1 && ./configure --prefix=/usr --sysconfdir=/etc --with-libevent --disable-shared && make -j2 && make DESTDIR=/install install
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends dns-root-data python3 ca-certificates libssl3 libevent-2.1-7 libexpat1 bind9 ldnsutils && mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound && install -m 644 /usr/share/dns/root.key /var/lib/unbound/root.key && rm -rf /var/lib/apt/lists/*
COPY --from=unbound-build /install/usr/ /usr/
RUN printf 'include: "/etc/unbound/unbound.conf.d/rustwalld.conf"\nserver:\n    username: ""\n    chroot: ""\n    auto-trust-anchor-file: "/var/lib/unbound/root.key"\n' > /etc/unbound/unbound.conf
COPY unbound.conf /etc/unbound/unbound.conf.d/rustwalld.conf
COPY unbound-smoke.py /unbound-smoke.py
CMD ["python3", "/unbound-smoke.py"]

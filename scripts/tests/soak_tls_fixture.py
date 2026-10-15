"""Private short-lived certificate fixtures for collector TLS regressions."""
from pathlib import Path
import ssl
import subprocess


class Certificates:
    def __init__(self, directory):
        self.root = Path(directory)
        self.root.mkdir()
        self.ca = self.root / "ca.pem"
        self.run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-nodes", "-keyout", str(self.root / "ca-key.pem"), "-out", str(self.ca),
                 "-subj", "/CN=Collector fixture CA", "-days", "1",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        self.issue("trusted", "DNS:collector.test,IP:127.0.0.1,IP:::1")
        self.issue("cn-only", None)

    @staticmethod
    def run(*args):
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)

    def issue(self, name, san):
        self.run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-nodes", "-keyout", str(self.root / f"{name}-key.pem"),
                 "-out", str(self.root / f"{name}.csr"), "-subj", "/CN=collector.test")
        extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        extensions += "extendedKeyUsage=serverAuth\n"
        if san is not None:
            extensions += f"subjectAltName={san}\n"
        config = self.root / f"{name}.extensions"
        config.write_text(extensions)
        self.run("x509", "-req", "-in", str(self.root / f"{name}.csr"),
                 "-CA", str(self.ca), "-CAkey", str(self.root / "ca-key.pem"),
                 "-set_serial", "1" if san is not None else "2", "-days", "1",
                 "-extfile", str(config), "-out", str(self.root / f"{name}.pem"))

    def context(self, name="trusted"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / f"{name}.pem", self.root / f"{name}-key.pem")
        context.set_alpn_protocols(["h2", "http/1.1"])
        return context

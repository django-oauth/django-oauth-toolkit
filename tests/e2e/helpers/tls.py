"""
Generate an ephemeral self-signed certificate for the cross-site browser layer.

The third-party-cookie probe needs the OP session cookie to carry
``SameSite=None``, browsers only honour ``SameSite=None`` alongside ``Secure``,
and ``Secure`` requires a secure context. Plain HTTP on ``idp.test`` /
``rp.test`` therefore cannot express the behaviour under test at all, so both
servers are run over TLS with a throwaway certificate whose errors Playwright is
told to ignore.

``cryptography`` is already installed as a hard dependency of ``jwcrypto``.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(directory, hostnames, ip_addresses=("127.0.0.1",)):
    """Write a SAN certificate + key covering ``hostnames`` into ``directory``.

    Returns ``(cert_path, key_path)``. An EC/P-256 key keeps generation
    instantaneous; the certificate is valid for a day, far longer than any test
    session, and never leaves the temporary directory it is written to.
    """
    directory = Path(directory)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = [x509.DNSName(host) for host in hostnames]
    san += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "e2e-cert.pem"
    key_path = directory / "e2e-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path

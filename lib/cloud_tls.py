"""TLS for the OpenEO Cloud connection: verification against a pinned certificate.

ssl.openeo.uk presents a self-signed certificate (no SubjectAltName, valid to
Nov 2035), so neither the public CA bundle nor hostname verification can
establish who we are talking to. Instead we ship that exact certificate in the
repository (lib/cloud_certs/ssl.openeo.uk.pem), use it as the only trust
anchor, require full certificate-chain verification, and additionally compare
the SHA-256 fingerprint of the certificate the server presented with the pin.

If the cloud operator rotates the certificate, connections fail closed until
the new certificate is committed here.
"""
import hashlib
import hmac
import os
import ssl

PINNED_CERT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "cloud_certs", "ssl.openeo.uk.pem")

# SHA-256 of the DER encoding of the certificate in PINNED_CERT_FILE
PINNED_SHA256 = "69a81fad0a5e309a8ca9897ff0f540885e497a7cfa3e16e864722d6cb1049823"


def make_ssl_context(cert_file=PINNED_CERT_FILE):
    """Client context that trusts only the pinned certificate."""
    # Deliberately not ssl.create_default_context(): that would load the system
    # CA store (we do not want any other CA to be able to vouch for the cloud).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    # The pinned certificate carries no SAN/CN, so there is no name to check;
    # identity is established by the pin (see verify_pinned_peer).
    ctx.check_hostname = False
    ctx.load_verify_locations(cafile=cert_file)
    return ctx


def fingerprint_sha256(der_bytes):
    return hashlib.sha256(der_bytes).hexdigest()


def verify_pinned_peer(der_bytes, pinned=PINNED_SHA256):
    """Raise ssl.SSLError unless the peer certificate is exactly the pinned one."""
    if not der_bytes or not hmac.compare_digest(fingerprint_sha256(der_bytes), pinned):
        raise ssl.SSLError("OpenEO Cloud certificate does not match the pinned certificate")

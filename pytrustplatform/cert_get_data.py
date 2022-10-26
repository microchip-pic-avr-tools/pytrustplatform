"""
Helper functions for fetching data from a certificate
"""
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def create_cert_fingerprint(filename):
    """
    Create fingerprint of certificate

    :param filename: Certificate file
    :type filename: str
    :returns: ASCII hex encoded fingerprint
    :rtype: str
    """
    with open(filename, "rb") as certfile:
        cert = x509.load_pem_x509_certificate(data=certfile.read(), backend=default_backend())

    fingerprint = cert.fingerprint(hashes.SHA256())

    return binascii.b2a_hex(fingerprint).decode('ascii')


def cert_get_skid(filename):
    """
    Create Subject key identifier from a certificate.

    :param filename: Certificate file
    :type filename: str
    :returns: ASCII hex encoded subject key identifier
    :rtype: str
    """
    with open(filename, "rb") as certfile:
        cert = x509.load_pem_x509_certificate(data=certfile.read(), backend=default_backend())

    # The generated digest is the SHA1 hash of the subjectPublicKey ASN.1 bit string.
    # This is the first recommendation in RFC 5280 section 4.2.1.2
    skid = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())

    return binascii.b2a_hex(skid.digest).decode('ascii')

def _cert_get_common_name(data):
    """
    Get Subject Common Name from a certificate passed as data bytes

    :param data: Certificate data
    :type data:  bytes
    :returns: Subject Common Name from certificate
    :rtype: str
    """
    cert = x509.load_pem_x509_certificate(data=data, backend=default_backend())
    for fields in cert.subject:
        current = str(fields.oid)
        if "commonName" in current:
            common_name = fields.value

    return common_name

def cert_get_common_name(filename):
    """
    Get Subject Common Name from a certificate passed in by filename

    :param filename: Certificate file
    :type filename: str
    :returns: Subject Common Name from certificate
    :rtype: str
    """
    with open(filename, "rb") as certfile:
        return _cert_get_common_name(data=certfile.read())

def cert_get_common_name_from_pem(certificate):
    """
    Get Subject Common Name from certificate passed in as a PEM string

    :param certificate: Certificate in PEM format
    :type certificate: str or bytes
    :return: Subject Common Name from certificate
    :rtype: str
    """
    if isinstance(certificate, str):
        certificate = certificate.encode('ascii')

    return _cert_get_common_name(certificate)

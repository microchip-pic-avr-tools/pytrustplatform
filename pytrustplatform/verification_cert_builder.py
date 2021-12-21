"""
Verification certificate builder

This module supports building verification certificates
typically used for signer Certificate Authority (CA) verification
"""
from logging import getLogger
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from .ca_create import random_cert_sn


def build_verification_cert(signer_ca_cert_file, signer_ca_key_file, subject_cn, verification_cert_filename):
    """
    Build verification certificate

    The verification certificate is typically used to verify a Certificate Authority (CA) when registering the CA in
    a cloud provider.  The verification certificate is written to file.

    :param signer_ca_cert_file: File containing signer Certificate Authority certificate
    :type signer_ca_cert_file: str
    :param signer_ca_key_file: File containing signer Certificate Authority private key
    :type signer_ca_key_file: str
    :param subject_cn: Subject Common Name (CN) for the verification certificate.  For AWS this is the registration
        code required when registering a CA certificate (signer)
    :param verification_cert_filename: Name (path) of file to write verification certificate to
    :type verification_cert_filename: str
    :return: Verification certificate object
    :rtype: :class:`cryptography.x509.Certificate` object
    """
    logger = getLogger(__name__)

    with open(signer_ca_key_file, 'rb') as keyfile:
        signer_ca_priv_key = serialization.load_pem_private_key(
            data=keyfile.read(),
            password=None,
            backend=default_backend())

    with open(signer_ca_cert_file, 'rb') as certfile:
        signer_ca_cert = x509.load_pem_x509_certificate(data=certfile.read(), backend=default_backend())

    # Generate a verification certificate around the registration code (subject common name)
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(random_cert_sn(16))
    builder = builder.issuer_name(signer_ca_cert.subject)
    builder = builder.not_valid_before(datetime.utcnow().replace(tzinfo=timezone.utc))
    builder = builder.not_valid_after(builder._not_valid_before + timedelta(days=1))
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_cn)]))
    builder = builder.public_key(signer_ca_cert.public_key())
    verification_cert = builder.sign(
        private_key=signer_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=default_backend())

    # Write signer CA certificate to file for reference
    with open(verification_cert_filename, 'wb') as certfile:
        logger.info("Writing verification certificate to %s", certfile.name)
        certfile.write(verification_cert.public_bytes(encoding=serialization.Encoding.PEM))

    return verification_cert

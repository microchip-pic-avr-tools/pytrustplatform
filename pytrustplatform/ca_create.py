"""
CA certificate creation utilities
"""

from logging import getLogger
from os import urandom
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Default certificate attributes
DEFAULT_ORGANIZATION_NAME = u'Example Inc'
DEFAULT_ROOT_COMMON_NAME = u'Example Root CA'
DEFAULT_SIGNER_COMMON_NAME = u'Example Signer FFFF'


def random_cert_sn(size):
    """
    Create a positive, non-trimmable serial number for X.509 certificates
    :param size: size in bytes
    :return: random serial number
    """
    raw_sn = bytearray(urandom(size))
    raw_sn[0] = raw_sn[0] & 0x7F # Force MSB bit to 0 to ensure positive integer
    raw_sn[0] = raw_sn[0] | 0x40 # Force next bit to 1 to ensure the integer won't be trimmed in ASN.1 DER encoding
    return int.from_bytes(raw_sn, byteorder='big', signed=False)

def save_certificate(filename, certificate):
    """
    Writes a certificate to file using PEM encoding
    :param filename: file to write to
    :param certificate: certificate to write
    """
    # Write certificate to file
    logger = getLogger(__name__)
    with open(filename, 'wb') as file:
        logger.debug("Saving to '%s'", file.name)
        file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

def load_certificate(certificate_path):
    """
    Loads a certificate from file
    :param certificate_path: path to file to load
    :return: certificate data
    """
    logger = getLogger(__name__)
    # Open certificate
    with open(certificate_path, 'rb') as file:
        logger.debug("Loading from %s", file.name)
        return x509.load_pem_x509_certificate(data=file.read(), backend=default_backend())

def load_csr(csr_path):
    """
    Loads a CSR from file
    :param csr_path: path to request to load
    """
    logger = getLogger(__name__)
    # Open CSR file
    with open(csr_path, 'rb') as file:
        logger.debug("Loading from %s", file.name)
        return x509.load_pem_x509_csr(file.read(), backend=default_backend())


def save_key(filename, key):
    """
    Writes a key to file using PEM encoding
    :param filename: file to write to
    :param key: key to write
    """
    logger = getLogger(__name__)
    # Write key to file
    with open(filename, 'wb') as file:
        logger.debug("Saving to '%s'", file.name)
        pem_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        file.write(pem_key)

def load_key(filename):
    """
    Loads an existing key from file
    :param filename: key to load
    :return: key loaded
    """
    logger = getLogger(__name__)
    with open(filename, 'rb') as file:
        logger.debug("Loading from '%s'", file.name)
        key = serialization.load_pem_private_key(
            data=file.read(),
            password=None,
            backend=default_backend())
    return key

def load_or_create_key(filename, force_create=False):
    """
    Attempts to load a key from file
    If the file does not exist, a new key is created and written to file.
    :param filename: file to attempt to open or create
    :param force: create a new key even if it exists already
    :return: key content
    """
    logger = getLogger(__name__)
    # Create or load a root CA key pair

    # Try to load existing key first
    if not force_create:
        try:
            return load_key(filename)
        except FileNotFoundError:
            logger.info("No key file found")

    logger.info("Generating new key")
    # No private key loaded, generate new one
    key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    # Save private key to file
    save_key(filename, key)
    return key

def add_signer_extensions(builder, public_key=None, authority_cert=None):
    """
    Add signer extensions to certificate builder
    :param builder: certificate builder
    :param public_key: public key to use (default: taken from builder)
    :param authority_cert: optional authority certificate
    """
    if public_key is None:
        # Public key not specified, assume its in the builder (cert builder)
        public_key = builder._public_key

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False),
        critical=True)

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False)

    # Save newly created subj key id extension
    subj_key_id_ext = builder._extensions[-1]

    if authority_cert:
        # We have an authority certificate, use its subject key id
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                authority_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value),
            critical=False)
    else:
        # No authority cert, assume this is a CSR and just use its own subject key id
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subj_key_id_ext.value),
            critical=False)

    return builder

def ca_create_root(root_ca_key_path, root_ca_cert_path, force=False,
                   org_name=DEFAULT_ORGANIZATION_NAME, common_name=DEFAULT_ROOT_COMMON_NAME):
    """
    Creates a CA Root Certificate
    :param root_ca_key_path: path to look for private key (or place key if created)
    :param root_ca_cert_path: path to store certificate
    :param force: Force re-creation of existing certificate
    :param org_name: Specify Organization Name attribute
    :param common_name: Specify Common Name attribute
    """
    logger = getLogger(__name__)

    if not force:
        # Will not re-create existing certificate file unless force is set
        try:
            with open(root_ca_cert_path, "rb"):
                logger.info("Root CA certificate file '%s' already exists, skipping (force=False)", root_ca_cert_path)
                return
        except FileNotFoundError:
            pass

    if org_name == DEFAULT_ORGANIZATION_NAME:
        logger.warning("Default organization name '%s' used for root certificate",
                       DEFAULT_ORGANIZATION_NAME)
    if common_name == DEFAULT_ROOT_COMMON_NAME:
        logger.warning("Default common name '%s' used for root certificate",
                       DEFAULT_ROOT_COMMON_NAME)


    # Create or load a root CA key pair
    logger.info("Loading root CA key")
    root_ca_priv_key = load_or_create_key(root_ca_key_path, force_create=force)

    # Create root CA certificate
    logger.info("Generating self-signed root CA certificate")
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(random_cert_sn(16))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)]))
    builder = builder.not_valid_before(datetime.utcnow().replace(tzinfo=timezone.utc))
    builder = builder.not_valid_after(builder._not_valid_before + timedelta(days=365*25))
    builder = builder.subject_name(builder._issuer_name)
    builder = builder.public_key(root_ca_priv_key.public_key())
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(root_ca_priv_key.public_key()),
        critical=False)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True)
    # Self-sign certificate
    root_ca_cert = builder.sign(
        private_key=root_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=default_backend())

    # Write root CA certificate to file
    save_certificate(root_ca_cert_path, root_ca_cert)
    logger.info("Root CA certificate created")

def ca_create_signer_csr(signer_ca_key_path, signer_ca_csr_path, force=False,
                         org_name=DEFAULT_ORGANIZATION_NAME, common_name=DEFAULT_SIGNER_COMMON_NAME):
    """
    Create a signer Certificate Signing Request (CSR)
    :param signer_ca_key_path: path to signer CA key
    :param signer_ca_csr_path: path to signer CA certificate signing request
    :param force: Force re-creation of existing certificate
    :param org_name: Specify Organization Name attribute
    :param common_name: Specify Common Name attribute
    """
    logger = getLogger(__name__)

    if not force:
        # Will not re-create existing certificate file unless force is set
        try:
            with open(signer_ca_csr_path, "rb"):
                logger.info("Signer CSR file file  '%s' already exists, skipping (force=False)", signer_ca_csr_path)
                return
        except FileNotFoundError:
            pass

    if org_name == DEFAULT_ORGANIZATION_NAME:
        logger.warning("Default organization name '%s' used for signer certificate",
                       DEFAULT_ORGANIZATION_NAME)
    if common_name == DEFAULT_SIGNER_COMMON_NAME:
        logger.warning("Default common name '%s' used for signer certificate",
                       DEFAULT_SIGNER_COMMON_NAME)

    # Load or create a signer CA key pair
    logger.info("Loading signer CA key")
    signer_ca_priv_key = load_or_create_key(signer_ca_key_path, force_create=force)

    logger.info("Generating signer CA CSR")
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)]))
    builder = add_signer_extensions(
        builder=builder,
        public_key=signer_ca_priv_key.public_key())
    signer_ca_csr = builder.sign(
        private_key=signer_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=default_backend())

    # Save CSR
    save_certificate(signer_ca_csr_path, signer_ca_csr)
    logger.info("Signer CSR created")

def ca_create_signer(signer_ca_csr_path, signer_ca_cert_path, root_ca_key_path, root_ca_cert_path, force=False):
    """
    Create signer certificate
    :param signer_ca_csr_path: path to signer CA certificate signing request
    :param signer_ca_cert_path: path to store signer CA certificate
    :param root_ca_key_path: path to look for private key
    :param root_ca_cert_path: path to root CA certificate
    :param force: Force re-creation of existing certificate
    """
    logger = getLogger(__name__)

    if not force:
        # Will not re-create existing certificate file unless force is set
        try:
            with open(signer_ca_cert_path, "rb"):
                logger.info("Signer CA certificate '%s' already exists, skipping (force=False)", signer_ca_cert_path)
                return
        except FileNotFoundError:
            pass

    logger.info("Loading signer CA CSR")
    try:
        signer_ca_csr = load_csr(signer_ca_csr_path)
    except FileNotFoundError:
        logger.error("Unable to find CA CSR file: %s", signer_ca_csr_path)
        raise

    # Check signature validity
    if not signer_ca_csr.is_signature_valid:
        raise RuntimeError('Signer CA CSR has invalid signature.')

    logger.info("Loading root CA key")
    try:
        root_ca_priv_key = load_key(root_ca_key_path)
    except FileNotFoundError:
        logger.error("Unable to find CA key file: %s", root_ca_key_path)
        raise

    logger.info("Loading root CA certificate")
    try:
        root_ca_cert = load_certificate(root_ca_cert_path)
    except FileNotFoundError:
        logger.error("Unable to find root CA certificate file: %s", root_ca_cert_path)
        raise

    # Create signer CA certificate
    logger.info("Generating signer CA certificate from CSR")

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(random_cert_sn(16))
    builder = builder.issuer_name(root_ca_cert.subject)
    not_before = datetime.utcnow().replace(tzinfo=timezone.utc)
    if not_before.month == 2 and not_before.day == 29:
        # Compressed certs don't handle leap years, fudge the date a little
        not_before.day = 28
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_before.replace(year=not_before.year + 10))
    builder = builder.subject_name(signer_ca_csr.subject)
    builder = builder.public_key(signer_ca_csr.public_key())
    builder = add_signer_extensions(
        builder=builder,
        authority_cert=root_ca_cert)
    # Sign signer certificate with root
    signer_ca_cert = builder.sign(
        private_key=root_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=default_backend())

    # Write signer CA certificate to file
    save_certificate(signer_ca_cert_path, signer_ca_cert)
    logger.info("Signer CA certificate created")

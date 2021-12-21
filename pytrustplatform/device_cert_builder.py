"""
Device certificate builder

This module supports building device certificates from device Certificate Signer Requests (CSR)
"""
import binascii
import datetime
import os.path
from logging import getLogger
import hashlib
import pytz
import asn1crypto.pem
from asn1crypto.keys import ECPointBitString
from asn1crypto.algos import DSASignature
from asn1crypto.csr import CertificationRequest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

#pylint: disable=wrong-import-position
# This module uses pykitcommander:
# Functions in this module make use of the pykitcommander package to:
# - program application firmware on to the MCU based on the APPLICATION
# - handle protocol framing according to the firmware driver
APPLICATION = "iotprovision"
APPLICATION_PROTOCOL_ID = "ProvisioningV2"

from .pytrust_errors import PytrustCertificateError

DEVICE_CSR_TEMPLATE_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "certs", "template_device.csr")

# Organization name used in certificates and signing requests
ORG_NAME = 'Microchip Technology Inc'

#pylint: disable=protected-access
def device_cert_sn(size, builder):
    """
    Generate Certificate serial number

    Cert serial number is the SHA256(Subject public key + Encoded dates)
    :param size: Serial number length in bytes
    :type size: int
    :param builder: x509 certificate builder
    :type builder: :class:`cryptography.x509.CertificateBuilder` object
    :return: Certificate serial number
    :rtype: int
    """
    # Get the public key as X and Y integers concatenated
    pub_nums = builder._public_key.public_numbers()
    pubkey = pub_nums.x.to_bytes(32, byteorder='big', signed=False)
    pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)

    # Get the encoded dates
    expire_years = 0
    enc_dates = bytearray(b'\x00'*3)
    enc_dates[0] = (enc_dates[0] & 0x07) \
                   | ((((builder._not_valid_before.year - 2000) & 0x1F) << 3) & 0xFF)
    enc_dates[0] = (enc_dates[0] & 0xF8) \
                   | ((((builder._not_valid_before.month) & 0x0F) >> 1) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x7F) \
                   | ((((builder._not_valid_before.month) & 0x0F) << 7) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x83) | (((builder._not_valid_before.day & 0x1F) << 2) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0xFC) | (((builder._not_valid_before.hour & 0x1F) >> 3) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0x1F) | (((builder._not_valid_before.hour & 0x1F) << 5) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0xE0) | ((expire_years & 0x1F) & 0xFF)
    enc_dates = bytes(enc_dates)

    # SAH256 hash of the public key and encoded dates
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pubkey)
    digest.update(enc_dates)
    raw_sn = bytearray(digest.finalize()[:size])
    raw_sn[0] = raw_sn[0] & 0x7F # Force MSB bit to 0 to ensure positive integer
    raw_sn[0] = raw_sn[0] | 0x40 # Force next bit to 1 to ensure the integer
                                 # won't be trimmed in ASN.1 DER encoding
    return int.from_bytes(raw_sn, byteorder='big', signed=False)

def build_device_csr(firmware_driver, csr_filename, common_name, force=False):
    """
    Build device Certificate Signing Request

    Build a device CSR from a template.  The CSR is used when building a device certificate.

    :param firmware_driver: Protocol driver instance for communicating with firmware on the MCU
    :param csr_filename: Name of file to write the generated CSR to.
    :type csr_filename: str
    :param common_name: Subject Common Name (CN) to use in the CSR.  This is typically a unique name or ID for this
        device
    :param force: Force creating new certificate overwriting pre-existing output file
    :type force: bool
    :return: Device Certificate Signing Request
    :rtype: class:`cryptography.x509.CertificateSigningRequest` object
    """
    logger = getLogger(__name__)

    if not force:
        try:
            # If the CSR file already exists, read it instead of re-creating it
            with open(csr_filename, "rb") as f:
                logger.info("CSR already exists and will not be regenerated (force=False)")
                logger.info("Reading existing device CSR from '%s'", csr_filename)
                return x509.load_pem_x509_csr(data=f.read(), backend=default_backend())
        except FileNotFoundError:
            pass

    with open(DEVICE_CSR_TEMPLATE_FILE, 'rb') as template_file:
        logger.debug("Using %s as CSR template", template_file.name)
        csr_template = template_file.read()
    _, _, csr_der = asn1crypto.pem.unarmor(csr_template)
    csr = CertificationRequest.load(csr_der)

    # The firmware driver wraps a serial port connection which enables a simple command-response transaction
    # This driver structure is defined in pykitcommander.firmwareinterface

    # Send firmware command to read the public key
    pubkey = firmware_driver.firmware_command("MC+ECC+GENPUBKEY")
    _csr_set_pubkey(csr, pubkey)

    # No extensions

    # Personalize CSR by setting custom Issuer Organization and Subject Common Name
    # This is not strictly necessary as this info is not used when creating the device certificate, but might be useful
    # if the CSR will be used somewhere else
    _csr_set_cn_and_org(csr, common_name, ORG_NAME)

    # Create a digest/hash for the CSR that can be sent to the ECC for signing
    csr_digest = hashlib.sha256(csr['certification_request_info'].dump()).digest()

    # Send firmware command to sign the digest
    signature = firmware_driver.firmware_command("MC+ECC+SIGNDIGEST",
                                                 [len(binascii.b2a_hex(csr_digest))],
                                                 binascii.b2a_hex(csr_digest))


    _csr_add_signature(csr, signature)

    # Convert the CSR to a cryptography.x509.CertificateSigningRequest object
    x509_csr = x509.load_der_x509_csr(csr.dump(), default_backend())

    # Print the CSR to file
    if not x509_csr.is_signature_valid:
        raise PytrustCertificateError('Device CSR has invalid signature.')
    with open(csr_filename, 'wb') as csrfile:
        logger.info("Saving to %s", csrfile.name)
        csrfile.write(x509_csr.public_bytes(encoding=serialization.Encoding.PEM))
        logger.info("Wrote device CSR to '%s'", csr_filename)

    return x509_csr

def _csr_set_pubkey(csr, pubkey):
    # Create the raw DER encoding and load it into the ECPointString class.
    ecpoint = ECPointBitString().load(b"\x03\x42\x00\x04" + binascii.a2b_hex(pubkey))
    csr['certification_request_info']['subject_pk_info']['public_key'] = ecpoint

def _csr_set_cn_and_org(csr, common_name, org):
    subject_info = {"common_name": common_name, "organization_name": org}
    csr['certification_request_info']['subject'] = asn1crypto.x509.Name.build(subject_info)

def _csr_add_signature(csr, signature):
    dsa_sig = DSASignature().from_p1363(binascii.a2b_hex(signature))
    csr['signature'] = dsa_sig.dump()

def build_device_cert(firmware_driver,
                      signer_ca_cert_file, signer_ca_key_file,
                      csr_filename, cert_filename,
                      force=False):
    """
    Build device certificate

    Uses serial number from ECC and Certificate Signer Request (CSR) to generate a device certificate
    The certificate is written to file and returned

    :param firmware_driver: Protocol driver instance for communicating with firmware on the MCU
    :param signer_ca_cert_file: File containing signer Certificate Authority certificate
    :type signer_ca_cert_file: str
    :param signer_ca_key_file: File containing signer Certificate Authority private key
    :type signer_ca_key_file: str
    :param csr_filename: Name of file to write the generated CSR to.
    :type csr_filename: str
    :param cert_filename: Name of file to write the generated certificate to
    :type cert_filename: str
    :param force: Force creating new certificate overwriting pre-existing output file
    :type force: bool
    :return: Device certificate
    :rtype: :class:`cryptography.x509.Certificate` object
    :raises PytrustCertificateError: If something is wrong with the CSR signature
    """
    logger = getLogger(__name__)

    if not force:
        try:
            # If the device cert file already exists, read it instead of re-creating it
            with open(cert_filename, "rb") as f:
                logger.info("Device certificate already exists and will not be regenerated (force=False)")
                logger.info("Reading existing device certificate from '%s'", cert_filename)
                return x509.load_pem_x509_certificate(data=f.read(), backend=default_backend())
        except FileNotFoundError:
            pass

    # Read signer CA private key from file and parse it
    with open(signer_ca_key_file, 'rb') as keyfile:
        logger.info("Loading signer CA key from %s", keyfile.name)
        signer_ca_priv_key = serialization.load_pem_private_key(
            data=keyfile.read(),
            password=None,
            backend=default_backend())

    # Read signer CA certificate from file and parse it
    with open(signer_ca_cert_file, 'rb') as certfile:
        logger.info("Loading signer CA certificate from %s", certfile.name)
        signer_ca_cert = x509.load_pem_x509_certificate(data=certfile.read(), backend=default_backend())

    # The firmware driver wraps a serial port connection which enables a simple command-response transaction
    # This driver structure is defined in pykitcommander.firmwareinterface

    # Send firmware command to read the ECC serial number
    logger.info("Reading ECC serial number")
    ecc_serial_number = firmware_driver.firmware_command("MC+ECC+SERIAL")

    common_name = 'sn{}'.format(ecc_serial_number)

    device_csr = build_device_csr(firmware_driver, csr_filename, common_name, force)

    logger.info("Generating device certificate from CSR")
    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(signer_ca_cert.subject)
    # Device cert must have minutes and seconds set to 0
    builder = builder.not_valid_before(datetime.datetime.now(tz=pytz.utc).replace(minute=0, second=0))
    # Should be year 9999, but this doesn't work on windows
    builder = builder.not_valid_after(datetime.datetime(3000, 12, 31, 23, 59, 59))

    subject_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, ORG_NAME),
                              x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    builder = builder.subject_name(subject_name)
    builder = builder.public_key(device_csr.public_key())
    # Device certificate is generated from certificate dates and public key
    builder = builder.serial_number(device_cert_sn(16, builder))
    # Add in extensions specified by CSR
    for extension in device_csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    # Subject Key ID is used as the thing name and MQTT client ID and is required for this demo
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(builder._public_key),
        critical=False)
    issuer_ski = signer_ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski.value),
        critical=False)

    # Sign certificate
    device_cert = builder.sign(
        private_key=signer_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=default_backend())

    # Save certificate for reference
    with open(cert_filename, 'wb') as certfile:
        logger.info("Saving to %s", certfile.name)
        certfile.write(device_cert.public_bytes(encoding=serialization.Encoding.PEM))
        logger.info("Wrote device certificate to '%s'", cert_filename)


    return device_cert

"""
Unittests for the verification_cert_builder module
"""
import unittest
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend as default_crypto_backend
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from pytrustplatform.verification_cert_builder import build_verification_cert

DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'output',
                             'verification_cert_builder_test_output')

SIGNER_CA_CERT_FILE = os.path.join(DATA_FOLDER, "dummy_signer-ca.crt")
SIGNER_CA_KEY_FILE = os.path.join(DATA_FOLDER, "dummy_signer-ca.key")

VERIFICATION_CERT_FILENAME = os.path.join(OUTPUT_FOLDER, "generated_verification.crt")

DUMMY_REGCODE = "Dummy012345"

class TestVerificationCertBuilder(unittest.TestCase):
    """Unittests for functions in the verification_cert_builder module"""

    def setUp(self):
        # Create output folder
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    def _check_verification_certificate(self, verification_cert, signer_cert_path):
        """Validating verification certificate based on provided signer certificate

        :param verification_cert: Device certificate to validate
        :type verification_cert: :class:`cryptography.x509.Certificate` object
        :param signer_cert: Signer certificate file (path) used when generating the device certificate
        :type signer_cert: str
        """
        # Load signer certificate
        with open(signer_cert_path, "rb") as signerfile:
            signer_certificate = signerfile.read()
        signer_cert = x509.load_pem_x509_certificate(signer_certificate, default_crypto_backend())
        # Use the provided signer certificate to validate the verification certificate
        try:
            signer_cert.public_key().verify(verification_cert.signature,
                                            verification_cert.tbs_certificate_bytes,
                                            ECDSA(verification_cert.signature_hash_algorithm))
        except crypto_exceptions.InvalidSignature:
            self.fail(msg="Verification of verification certificate failed")

        # Check the Subject Common Name (registration code)
        self.assertEqual(verification_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
                         DUMMY_REGCODE,
                         msg="Unexpected Device Certificate Subject Common Name")

    def test_build_ca_verification_cert(self):
        """ Tests building a CA verification certificate """
        ver_cert = build_verification_cert(SIGNER_CA_CERT_FILE,
                                           SIGNER_CA_KEY_FILE,
                                           DUMMY_REGCODE,
                                           VERIFICATION_CERT_FILENAME)

        self._check_verification_certificate(ver_cert, SIGNER_CA_CERT_FILE)

        with open(VERIFICATION_CERT_FILENAME, "rb") as certfile:
            ver_cert_from_file = x509.load_pem_x509_certificate(data=certfile.read(), backend=default_crypto_backend())

        self.assertEqual(ver_cert_from_file.public_bytes(encoding=serialization.Encoding.PEM),
                         ver_cert.public_bytes(encoding=serialization.Encoding.PEM))

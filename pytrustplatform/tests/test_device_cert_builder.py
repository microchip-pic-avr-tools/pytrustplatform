"""
Unit tests for device_cert_builder module
"""
import os
import unittest
from mock import patch
from mock import MagicMock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend as default_crypto_backend
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography import x509

from pytrustplatform.device_cert_builder import build_device_cert, build_device_csr

DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output', 'device_cert_builder_test_output')

# File for generated device certificate
DEVICE_CERT_FILE = os.path.join(OUTPUT_FOLDER, 'generated_device.crt')

# File for generated device Certificate Signer Request (CSR) when building device certificate
DEVICE_CSR_FILE_CERT_BUILD = os.path.join(OUTPUT_FOLDER, 'build_cert_generated_device.csr')

# File for generated device Certificate Signer Request (CSR) when building CSR only
DEVICE_CSR_FILE_CSR_BUILD = os.path.join(OUTPUT_FOLDER, 'build_csr_generated_device.csr')

# File with signer CA certificate used in the tests
SIGNER_CA_CERT_FILE = os.path.join(DATA_FOLDER, 'dummy_signer-ca.crt')

# File with signer CA private key used in the tests
SIGNER_CA_KEY_FILE = os.path.join(DATA_FOLDER, 'dummy_signer-ca.key')

# Some data used in the tests
PUB_KEY_PREAMBLE = b"\x03\x42\x00\x04"
CSR = "3081FB3081A2020100302F31143012060355040A0C0B4578616D706C6520496E633117301506035504030C0E4578616D706C6520"\
            "4465766963653059301306072A8648CE3D020106082A8648CE3D03010703420004C0A6652098320E6FCEBF894257E75D9875D84A"\
            "5D620DA6512399C49F02B8C685E3F6C111E0241192E9A9095A15FAAAA99276959D1E57CC06A4F8D0DE8AA62A42A011300F06092A"\
            "864886F70D01090E31023000300A06082A8648CE3D040302034800304502200AD438DEFFE104CE3396CCF5ABAC1813C0209247D0"\
            "B4881B520CF79CBD5D18A3022100AEB6D449F86F7E0213CFE07E93DA1A6669D29EA7C3A9434FEFD23C369B0D0903"
CSR_SIGNATURE = "3B0361EA5130DBA7DFE64B8122086DEA1C984B695EC18034A974931727363F13944502F72373B9F453695490B317B0FF94C7"\
                "F31E9E306494A0A987F216D4E07E"
PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\n'\
                   b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwKZlIJgyDm/Ov4lCV+ddmHXYSl1i\nDaZRI5nEnwK4xoXj9sER4CQRkumpCV'\
                   b'oV+qqpknaVnR5XzAak+NDeiqYqQg==\n'\
                   b'-----END PUBLIC KEY-----\n'
PUBLIC_KEY_FROM_TARGET = "C0A6652098320E6FCEBF894257E75D9875D84A5D620DA6512399C49F02B8C685E3F6C111E0241192E9A9095"\
                               "A15FAAAA99276959D1E57CC06A4F8D0DE8AA62A42"
ECC_SERIAL = "012355619A4B62CDFE"
DEVICE_COMMON_NAME = "sn012355619A4B62CDFE"
DEVICE_ORG = "Microchip Technology Inc"

class TestDeviceCertBuilder(unittest.TestCase):
    """Unit tests for functions in device_cert_builder module"""

    def setUp(self):
        # Set some default values for the FW request stub
        # These can be overridden by the tests if needed
        self.devkey_response = PUBLIC_KEY_FROM_TARGET
        self.devsign_response = CSR_SIGNATURE

        # Clean up by removing any files from previously test runs
        if os.path.exists(OUTPUT_FOLDER):
            for outfile in os.listdir(OUTPUT_FOLDER):
                try:
                    os.remove(outfile)
                except FileNotFoundError:
                    # Could be that no files exists so just ignore any errors
                    pass

        # Create output folder
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    def _mock_firmware(self, cmd, args=None, payload=None):
        """
        Mock out provisioning firmware with appropriate responses
        """
        if cmd.startswith("MC+ECC+SERIAL"):
            return ECC_SERIAL
        if cmd.startswith("MC+ECC+GENPUBKEY"):
            return PUBLIC_KEY_FROM_TARGET
        if cmd.startswith("MC+SETLED"):
            return "OK"
        if cmd.startswith("MC+ECC+SIGNDIGEST"):
            return CSR_SIGNATURE
        return "Oh dear. Function not mocked."

    def _mock_serialport(self):
        """
        Create a mock of the serial port object
        """
        mock_serialport_patch = patch("pytrustplatform.cli_certificate_main.SerialCDC")
        self.addCleanup(mock_serialport_patch.stop)
        mock_serialport_patch.start()

    def _mock_firmwaredriver(self):
        """
        Create a mock of the firmwaredriver object

        :returns: Mock of firmware driver instance
        """
        mock_firmwaredriver = MagicMock()
        mock_firmwaredriver.firmware_command.side_effect = self._mock_firmware
        return mock_firmwaredriver

    def _check_device_certificate(self, device_cert, signer_cert_path):
        """Validating device certificate based on provided signer certificate

        :param device_cert: Device certificate to validate
        :type device_cert: :class:`cryptography.x509.Certificate` object
        :param signer_cert: Signer certificate file (path) used when generating the device certificate
        :type signer_cert: str
        """
        # Load signer certificate
        with open(signer_cert_path, "rb") as signerfile:
            signer_certificate = signerfile.read()
        signer_cert = x509.load_pem_x509_certificate(signer_certificate, default_crypto_backend())
        # Use the provided signer certificate to validate the device certificate
        try:
            signer_cert.public_key().verify(device_cert.signature,
                                            device_cert.tbs_certificate_bytes,
                                            ECDSA(device_cert.signature_hash_algorithm))
        except crypto_exceptions.InvalidSignature:
            self.fail(msg="Verification of device certificate failed")

        # Check that the ECC serial number (+ 'sn' prefix) was used as Subject Common Name
        self.assertEqual(device_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
                         DEVICE_COMMON_NAME,
                         msg="Unexpected Device Certificate Subject Common Name")

    def _check_device_csr(self, csr):
        self.assertEqual(len(csr.extensions), 0, msg="There should be no extensions in the device CSR")
        self.assertEqual(csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
                         DEVICE_COMMON_NAME,
                         msg="Unexpected Device CSR Subject Common Name")
        self.assertEqual(csr.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value,
                         DEVICE_ORG,
                         msg="Unexpected Device CSR Subject Organization Name")

        self.assertEqual(csr.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo),
                         PUBLIC_KEY,
                         msg="Unexpected device CSR Public Key")
        self.assertTrue(csr.is_signature_valid)

    def test_build_device_cert(self):
        """Testing device certificate building, normal case, no errors"""
        mock_fw_driver = self._mock_firmwaredriver()
        device_cert = build_device_cert(mock_fw_driver,
                                        SIGNER_CA_CERT_FILE,
                                        SIGNER_CA_KEY_FILE,
                                        DEVICE_CSR_FILE_CERT_BUILD,
                                        DEVICE_CERT_FILE,
                                        force=True)

        self._check_device_certificate(device_cert, SIGNER_CA_CERT_FILE)

        with open(DEVICE_CERT_FILE, "rb") as certfile:
            device_cert_from_file = x509.load_pem_x509_certificate(data=certfile.read(),
                                                                   backend=default_crypto_backend())

        self._check_device_certificate(device_cert_from_file, SIGNER_CA_CERT_FILE)

        with open(DEVICE_CSR_FILE_CERT_BUILD, "rb") as csrfile:
            device_csr = x509.load_pem_x509_csr(data=csrfile.read(), backend=default_crypto_backend())

        self._check_device_csr(device_csr)

    def test_build_device_csr(self):
        """Test generating device CSR, normal case, no errors"""
        mock_fw_driver = self._mock_firmwaredriver()
        generated_csr = build_device_csr(mock_fw_driver, DEVICE_CSR_FILE_CSR_BUILD, DEVICE_COMMON_NAME, force=True)

        with open(DEVICE_CSR_FILE_CSR_BUILD, 'rb') as csr_file:
            csr_from_file = x509.load_pem_x509_csr(data=csr_file.read(), backend=default_crypto_backend())

        self._check_device_csr(csr_from_file)
        self.assertEqual(csr_from_file.public_bytes(encoding=serialization.Encoding.PEM),
                         generated_csr.public_bytes(encoding=serialization.Encoding.PEM))

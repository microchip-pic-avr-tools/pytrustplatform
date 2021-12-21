"""
Certificates CLI tests
"""
import unittest
import os
import sys
import shutil
from io import StringIO
from mock import patch
from mock import MagicMock
from mock import ANY
from cryptography.hazmat.backends import default_backend as default_crypto_backend
from cryptography import x509
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from pykitcommander.kitcommandererrors import KitCommunicationError
from pykitcommander.kitmanager import WifiKitLeds
from pytrustplatform.cli_pytrust import main
from pytrustplatform.tests.data import dummy_cert
from pytrustplatform.pytrust_errors import PytrustCertificateError

DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
CERTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../certs/RootCA')

LOG_FOLDER = os.path.join(OUTPUT_FOLDER, "test_cli_log_files")
CERT_FOLDER = DATA_FOLDER
CERT_FILE = os.path.join(DATA_FOLDER, 'dummy_cert.crt')
ECC_CERT_OUTPUT_FOLDER = os.path.join(OUTPUT_FOLDER, "test_ecc_cert_output_files")
CERT_FROM_CSR_OUTPUT_FOLDER = os.path.join(OUTPUT_FOLDER, "test_csr_cert_output_files")
VERIFICATION_OUTPUT_FOLDER = os.path.join(OUTPUT_FOLDER, "test_verification_output_files")

# File with signer CA certificate used in the tests
SIGNER_CA_CERT_FILE = os.path.join(DATA_FOLDER, 'dummy_signer-ca.crt')

# File with signer CA private key used in the tests
SIGNER_CA_KEY_FILE = os.path.join(DATA_FOLDER, 'dummy_signer-ca.key')

#pylint: disable=line-too-long
# Dummy ECC data
ECC_MAH1H_DATA = {
    "serial": "01230B2AC64F6E18FE",
    "slot12": b'2385439666007c07333a39f78cefdb4b6ba31c69cc542a40c51ceaccb0fac1de931b680cea42e65a1072ca3aada2bb8e272ae2b99efcfe112f7196113507483492deaa201b10a000',
    "slot10": b'74e9207bb4b10dce5350ab5dfdde625fabca02baa542933f76c22abd994489f0e98dd5a0bc9f7ae9bf919188749e9658f55c26f7a2631382d3886c1e2059774d9456e0201b20a000',
    "slot11": b'00000000b56546b3516fe9914095d52ad6cbdbf579df0f4cc0acf1e3001f0bd2d3081aa4000000006769ef1e05ddc8f2465c40a7bde8afa3ab89e3cff2e9d21a2cc57c13effbe75b',
    "slot5": b'00000000b56546b3516fe991',
    "devkey": b'b076a34443e74426eb40c3e31a7bdd94174e9fb8e6e2a711486e9a7f574475fb17db36c56a452a2491016abb759b59cee85593b10e55828bd44e6034192579fb'
}
ECC_MAH4I_DATA = {
    "serial": "01233BAEDAAEAA5501",
    "slot12": b'394ADFAA865449769BDBEC6198D184A2FD37CFD09434710EEC93B38ADB6252E295923729C412E2ABE955A738936995C81442A8D8EE8BF355F049A1FB0732A285963A9F2C2010A000',
    "slot10": b'5CB63359113027AB981EC780E2DA9F9D51FD4FBCBA1C223938A3977ABDF6E7412C2E7CFC407524DA2BC1DB1ADAE80164A8717386B59593A35257F75DCDB16F2AA326DC2C2030A000',
    "slot11": b'000000009972887C3660FB10873CFE81D037AEC66EE2DE3792561B62BE537AAEEF0E1D7200000000A3869F549A231369FCC1C32CCF958A260C66CECBF1316E00C78E7F536CC4AF14',
    "slot5": b'000000009972887C3660FB10873CFE81D037AEC66EE2DE3792561B62BE537AAEEF0E1D72',
    "devkey": b'0991CF36F4E15A6E52FC29779D2593285D32C161987ED82CDFE814A7AEF5200EFEC01C4EFA582297EFECDF8F6150396113E224A1D4738DD55F96F3409A3C1EE8'
}
ECC_MAH1H_SERIAL = "01230B2AC64F6E18FE"
ECC_MAH4I_SERIAL = "01233BAEDAAEAA5501"
DUMMY_SLOT12 = b'2385439666007c07333a39f78cefdb4b6ba31c69cc542a40c51ceaccb0fac1de931b680cea42e65a1072ca3aada2bb8e272ae2b99efcfe112f7196113507483492deaa201b10a000'
DUMMY_SLOT10 = b'74e9207bb4b10dce5350ab5dfdde625fabca02baa542933f76c22abd994489f0e98dd5a0bc9f7ae9bf919188749e9658f55c26f7a2631382d3886c1e2059774d9456e0201b20a000'
DUMMY_DEVKEY = b'b076a34443e74426eb40c3e31a7bdd94174e9fb8e6e2a711486e9a7f574475fb17db36c56a452a2491016abb759b59cee85593b10e55828bd44e6034192579fb'
DUMMY_SLOT11 = b'00000000b56546b3516fe9914095d52ad6cbdbf579df0f4cc0acf1e3001f0bd2d3081aa4000000006769ef1e05ddc8f2465c40a7bde8afa3ab89e3cff2e9d21a2cc57c13effbe75b'
DUMMY_SLOT5 = b'00000000b56546b3516fe991'

# Dummy Verification certificate data
DUMMY_REGCODE = "Dummy012345"

CLI_SUCCESS = 0
CLI_FAILURE = 1

class TestCliCertificate(unittest.TestCase):
    """Certificates CLI tests

    These tests are mostly integration tests verifying the whole stack
    """

    def setUp(self):
        # Modify log folder to avoid permission denied problems when running on Jenkins as the original
        # log folder location will be outside the workspace of the build job
        self.mock_user_log_dir_patch = patch('pytrustplatform.cli_pytrust.user_log_dir')
        self.addCleanup(self.mock_user_log_dir_patch.stop)
        self.mock_user_log_dir = self.mock_user_log_dir_patch.start()
        self.mock_user_log_dir.return_value = LOG_FOLDER

        # Set some default values for protocol mock return values
        # These can be overridden by the tests if needed
        self.ecc_data = ECC_MAH1H_DATA

    #pylint: disable=too-many-return-statements
    #pylint: disable=unused-argument
    def _read_ecc_slot_stub(self, slot_number, num_bytes):
        """Stub for mocking out the read_ecc_slot method of a firmware protocol driver

        :param slot_number: The slot_number argument sent into the read_ecc_slot method
        :type request: int
        :param num_bytes: The num_bytes argument sent into the read_ecc_slot method
        :type num_bytes: int
        """
        if slot_number == 5:
            return self.ecc_data['slot5']
        if slot_number == 10:
            return self.ecc_data['slot10']
        if slot_number == 11:
            return self.ecc_data['slot11']
        if slot_number == 12:
            return self.ecc_data['slot12']
        return None

    def _mock_firmware(self, cmd, args=None, payload=None):
        """
        Mock out provisioning firmware with appropriate responses
        """
        if cmd.startswith("MC+ECC+SERIAL"):
            return self.ecc_data["serial"]
        if cmd.startswith("MC+ECC+READ"):
            return self.ecc_data["slot{}".format(args[0])]
        if cmd.startswith("MC+ECC+GENPUBKEY"):
            return self.ecc_data["devkey"]
        if cmd.startswith("MC+SETLED"):
            return "OK"
        if cmd.startswith("MC+VERSION"):
            return "0.0.0"
        return "Oh dear. Function not mocked."

    def _mock_serialport(self):
        """
        Create a mock of the serial port object.
        It doesn't do anything, just prevents an open() attempt
        """
        mock_serialport_patch = patch("pytrustplatform.cli_certificate_main.SerialCDC")
        self.addCleanup(mock_serialport_patch.stop)
        mock_serialport_patch.start()

    def _mock_kit(self):
        """
        Create a mock of the setup_kit() helper
        """
        mock_setup_kit_patch = patch("pytrustplatform.cli_certificate_main.setup_kit")
        self.addCleanup(mock_setup_kit_patch.stop)
        mock_setup_kit = mock_setup_kit_patch.start()

        mock_firmwaredriver = MagicMock()
        mock_firmwaredriver_instance = MagicMock()
        mock_firmwaredriver.return_value = mock_firmwaredriver_instance

        # Redirect firmware_command calls to the firmware mock
        mock_firmwaredriver_instance.firmware_command.side_effect = self._mock_firmware
        # Create dummy kit_info but only add info needed by the tests
        dummy_kit_info = {'leds' : WifiKitLeds()}
        # Inject dummy values
        mock_setup_kit.return_value = {"port":"COM-1",
                                       "protocol_baud":9600,
                                       "protocol_id":"ProvisioningV2",
                                       "protocol_class" : mock_firmwaredriver,
                                       "kit_info" : dummy_kit_info}

    def test_get_skid(self):
        """ Tests reading of subject key identifier """
        testargs = ["pytrust", "certificate", "get-skid", "--cert", CERT_FILE]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue(dummy_cert.DUMMY_CERT_SKID in mock_stdout.getvalue(),
                                msg="Actual stdout: {}".format(mock_stdout.getvalue()))

        self.assertEqual(retval, CLI_SUCCESS)

    def test_get_skid_cert_alias(self):
        """
        Test the get-skid action with cert alias for the certificate command
        """
        testargs = ["pytrust", "cert", "get-skid", "--cert", CERT_FILE]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue(dummy_cert.DUMMY_CERT_SKID in mock_stdout.getvalue())

        self.assertEqual(retval, CLI_SUCCESS)

    def test_create_fingerprint(self):
        """ Tests generation of a certificate fingerprint """
        testargs = ["pytrust", "certificate", "fingerprint", "--cert", CERT_FILE]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue(dummy_cert.DUMMY_CERT_FINGERPRINT in mock_stdout.getvalue(),
                                msg="Actual stdout: {}".format(mock_stdout.getvalue()))

        self.assertEqual(retval, CLI_SUCCESS)

    @patch("pytrustplatform.cli_certificate_main.build_device_cert", autospec=True)
    def test_create_from_csr(self, mock_build_device_cert):
        """
        Tests command for creating device certificate from Certificate Signing Request (CSR)

        This test only excercises the CLI layer.  Everything else is mocked out (device_cert_builder)
        """
        self._mock_kit()
        self._mock_serialport()

        # Delete output folder upfront to check that pytrust is able to create the output folder if it does not exist
        try:
            shutil.rmtree(CERT_FROM_CSR_OUTPUT_FOLDER)
        except FileNotFoundError:
            # This is as expected if it is the first time the test is run
            pass

        testargs = ["pytrust", "certificate", "create-from-csr", "-o", CERT_FROM_CSR_OUTPUT_FOLDER, "--scac", SIGNER_CA_CERT_FILE, "--scak", SIGNER_CA_KEY_FILE, "-f"]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        self.assertEqual(retval, CLI_SUCCESS)

        mock_build_device_cert.assert_called_with(ANY,
                                                  signer_ca_cert_file=SIGNER_CA_CERT_FILE,
                                                  signer_ca_key_file=SIGNER_CA_KEY_FILE,
                                                  csr_filename=os.path.join(CERT_FROM_CSR_OUTPUT_FOLDER, "device.csr"),
                                                  cert_filename=os.path.join(CERT_FROM_CSR_OUTPUT_FOLDER, "device.crt"),
                                                  force=True)

        # Check that the output folder was created (it will be empty as the build_device_cert is mocked out)
        self.assertTrue(os.path.exists(CERT_FROM_CSR_OUTPUT_FOLDER))

    @patch("pytrustplatform.cli_certificate_main.build_device_cert", autospec=True)
    def test_create_from_csr_no_output_arg(self, mock_build_device_cert):
        """
        Simple test that checks the create-from-csr action when the output folder argument is missing

        This test only checks that the cert builder is called with the correct default output folder.  The rest is
        tested by the normal test (test_create_from_csr)
        """
        self._mock_kit()
        self._mock_serialport()
        testargs = ["pytrust", "certificate", "create-from-csr", "--scac", SIGNER_CA_CERT_FILE, "--scak", SIGNER_CA_KEY_FILE]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        self.assertEqual(retval, CLI_SUCCESS)

        mock_build_device_cert.assert_called_once()

        # Check the csr_filename argument
        self.assertEqual(mock_build_device_cert.call_args_list[0][0][3], os.path.join(".", "device.csr"))
        # Check the cert_filename argument
        self.assertEqual(mock_build_device_cert.call_args_list[0][0][4], os.path.join(".", "device.crt"))

    @patch("pytrustplatform.cli_certificate_main.build_device_cert", autospec=True)
    def test_create_from_csr_ca_cert_file_error(self, mock_build_device_cert):
        """
        Test error handling when CA certificate file does not exist
        """
        self._mock_kit()
        self._mock_serialport()
        mock_build_device_cert.side_effect = FileNotFoundError("Injected by mock")

        testargs = ["pytrust", "certificate", "create-from-csr", "--scac", "nofile.txt", "--scak", SIGNER_CA_KEY_FILE, "-f"]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        self.assertEqual(retval, CLI_FAILURE)


    @patch("pytrustplatform.cli_certificate_main.build_device_cert", autospec=True)
    def test_create_from_csr_ca_key_file_error(self, mock_build_device_cert):
        """
        Test error handling when CA key file does not exist
        """
        self._mock_kit()
        self._mock_serialport()
        mock_build_device_cert.side_effect = FileNotFoundError("Injected by mock")

        testargs = ["pytrust", "certificate", "create-from-csr", "--scac", SIGNER_CA_CERT_FILE, "--scak", "nofile.txt", "-f"]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        self.assertEqual(retval, CLI_FAILURE)

    @patch("pytrustplatform.cli_certificate_main.build_device_cert", autospec=True)
    def test_create_from_csr_when_pytrustcertificateerror(self, mock_build_device_cert):
        """
        Test error handling when build_device_cert raises PytrustCertificateError
        """
        self._mock_kit()
        self._mock_serialport()
        mock_build_device_cert.side_effect = PytrustCertificateError("Exception injected into mock")

        testargs = ["pytrust", "certificate", "create-from-csr", "--scac", SIGNER_CA_CERT_FILE, "--scak", SIGNER_CA_KEY_FILE]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        # This test does not seem to test much, but it actually checks that the CLI returns failure and that no
        # exceptions are raised, i.e. no stack trace in the face of the user
        self.assertEqual(retval, CLI_FAILURE)

    @patch("pytrustplatform.cli_certificate_main.build_device_cert", autospec=True)
    def test_create_from_csr_when_kitcommunicationerror(self, mock_build_device_cert):
        """
        Test error handling when a KitCommunicationError (this simulates a failing FW command)
        """
        self._mock_kit()
        self._mock_serialport()
        mock_build_device_cert.side_effect = KitCommunicationError("Exception injected into mock")

        testargs = ["pytrust", "certificate", "create-from-csr", "--scac", SIGNER_CA_CERT_FILE, "--scak", SIGNER_CA_KEY_FILE]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        # This test does not seem to test much, but it actually checks that the CLI returns failure and that no
        # exceptions are raised, i.e. no stack trace in the face of the user
        self.assertEqual(retval, CLI_FAILURE)

    @patch("pytrustplatform.cli_certificate_main.build_verification_cert", autospec=True)
    def test_create_verification(self, mock_build_verification_cert):
        """
        Test create-verification action normal case, no errors

        Only testing the CLI part, the verification certificate building is mocked out
        """
        testargs = ["pytrust", "certificate", "create-verification", "-o", VERIFICATION_OUTPUT_FOLDER, "--scac", SIGNER_CA_CERT_FILE, "--scak", SIGNER_CA_KEY_FILE, "--reg", DUMMY_REGCODE]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        ver_cert_filename = os.path.join(VERIFICATION_OUTPUT_FOLDER, "verification.crt")

        self.assertEqual(retval, CLI_SUCCESS)
        mock_build_verification_cert.assert_called_with(signer_ca_cert_file=SIGNER_CA_CERT_FILE,
                                                        signer_ca_key_file=SIGNER_CA_KEY_FILE,
                                                        subject_cn=DUMMY_REGCODE,
                                                        verification_cert_filename=ver_cert_filename)

    @patch("pytrustplatform.cli_certificate_main.build_verification_cert", autospec=True)
    def test_create_verification_when_key_file_error(self, mock_build_verification_cert):
        """
        Test create-verification action when signer CA key file does not exist
        """
        mock_build_verification_cert.side_effect = FileNotFoundError("Injected by mock")

        testargs = ["pytrust", "certificate", "create-verification", "-o", VERIFICATION_OUTPUT_FOLDER, "--scac", SIGNER_CA_CERT_FILE, "--scak", "nofile.key", "--reg", DUMMY_REGCODE]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        self.assertEqual(retval, CLI_FAILURE)

    @patch("pytrustplatform.cli_certificate_main.build_verification_cert", autospec=True)
    def test_create_verification_when_cert_file_error(self, mock_build_verification_cert):
        """
        Test create-verification action when signer CA cert file does not exist
        """
        mock_build_verification_cert.side_effect = FileNotFoundError("Injected by mock")

        testargs = ["pytrust", "certificate", "create-verification", "-o", VERIFICATION_OUTPUT_FOLDER, "--scac", "nofile.crt", "--scak", SIGNER_CA_KEY_FILE, "--reg", DUMMY_REGCODE]
        with patch.object(sys, 'argv', testargs):
            retval = main()

        self.assertEqual(retval, CLI_FAILURE)

    def test_read_ecc_serialnumber(self):
        """ Tests reading an ECC serialnumber """
        self._mock_kit()
        self._mock_serialport()
        testargs = ["pytrust", "certificate", "read-ecc-serialnumber"]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue("ECC serial number read" in mock_stdout.getvalue())
                self.assertTrue(self.ecc_data['serial'] in mock_stdout.getvalue())
                self.assertEqual(retval, CLI_SUCCESS)

    def test_create_certificates_from_mah1h_ecc(self):
        """ Tests generation of a certificate from ECC (MAH1H variant) information """
        self.ecc_data = ECC_MAH1H_DATA
        self._mock_kit()
        self._mock_serialport()
        # Create output folder
        os.makedirs(ECC_CERT_OUTPUT_FOLDER, exist_ok=True)
        testargs = ["pytrust", "certificate", "create-from-ecc", '-o', ECC_CERT_OUTPUT_FOLDER, '--force']
        with patch.object(sys, 'argv', testargs):
            retval = main()
            # Load Root CA, generated signer and generated device certificate
            with open(os.path.join(CERTS_FOLDER, "ATECC Root CA 001.crt"), "rb") as certfile:
                root_ca_certificate = certfile.read()
            with open(os.path.join(ECC_CERT_OUTPUT_FOLDER, "signer_ecc608.crt"), "rb") as certfile:
                signer_certificate = certfile.read()
            with open(os.path.join(ECC_CERT_OUTPUT_FOLDER, "device_ecc608.crt"), "rb") as certfile:
                device_certificate = certfile.read()
            root_ca_cert = x509.load_pem_x509_certificate(root_ca_certificate, default_crypto_backend())
            signer_cert = x509.load_pem_x509_certificate(signer_certificate, default_crypto_backend())
            device_cert = x509.load_pem_x509_certificate(device_certificate, default_crypto_backend())
            try:
                root_ca_cert.public_key().verify(signer_cert.signature, signer_cert.tbs_certificate_bytes, ECDSA(signer_cert.signature_hash_algorithm))
            except crypto_exceptions.InvalidSignature:
                self.fail(msg="Verification of signer certificate failed")
            try:
                signer_cert.public_key().verify(device_cert.signature, device_cert.tbs_certificate_bytes, ECDSA(device_cert.signature_hash_algorithm))
            except crypto_exceptions.InvalidSignature:
                self.fail(msg="Verification of device certificate failed")
            self.assertEqual(retval, CLI_SUCCESS)

    def test_create_certificates_from_mah4i_ecc(self):
        """ Tests generation of a certificate from ECC (MAH4I variant) information """
        self.ecc_data = ECC_MAH4I_DATA
        self._mock_kit()
        self._mock_serialport()
        # Create output folder
        os.makedirs(ECC_CERT_OUTPUT_FOLDER, exist_ok=True)
        testargs = ["pytrust", "certificate", "create-from-ecc", '-o', ECC_CERT_OUTPUT_FOLDER, '--force']
        with patch.object(sys, 'argv', testargs):
            retval = main()
            # Load Root CA, generated signer and generated device certificate
            with open(os.path.join(CERTS_FOLDER, "Crypto Authentication Root CA 002.crt"), "rb") as certfile:
                root_ca_certificate = certfile.read()
            with open(os.path.join(ECC_CERT_OUTPUT_FOLDER, "signer_ecc608.crt"), "rb") as certfile:
                signer_certificate = certfile.read()
            with open(os.path.join(ECC_CERT_OUTPUT_FOLDER, "device_ecc608.crt"), "rb") as certfile:
                device_certificate = certfile.read()
            root_ca_cert = x509.load_pem_x509_certificate(root_ca_certificate, default_crypto_backend())
            signer_cert = x509.load_pem_x509_certificate(signer_certificate, default_crypto_backend())
            device_cert = x509.load_pem_x509_certificate(device_certificate, default_crypto_backend())
            try:
                root_ca_cert.public_key().verify(signer_cert.signature, signer_cert.tbs_certificate_bytes, ECDSA(signer_cert.signature_hash_algorithm))
            except crypto_exceptions.InvalidSignature:
                self.fail(msg="Verification of signer certificate failed")
            try:
                signer_cert.public_key().verify(device_cert.signature, device_cert.tbs_certificate_bytes, ECDSA(device_cert.signature_hash_algorithm))
            except crypto_exceptions.InvalidSignature:
                self.fail(msg="Verification of device certificate failed")
            self.assertEqual(retval, CLI_SUCCESS)

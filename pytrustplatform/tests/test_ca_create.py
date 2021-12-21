import unittest
import tempfile
from os import path
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from pytrustplatform import ca_create

class TestCaCreateFunctions(unittest.TestCase):
    """
    Test generation of random certificate serial number
    """
    def test_sn(self):
        # Since this is a random number, do it a few times
        ITERATIONS = 1000
        for _ in range(ITERATIONS):
            size_bytes = 8
            # Calculate the max and min
            maximum = (0x80 << ((size_bytes-1)*8))-1
            minimum = 0x40 << ((size_bytes-1)*8)
            # Generate a serial number
            sn = ca_create.random_cert_sn(size_bytes)
            # Test that it is grater than zero
            self.assertGreater(sn, 0)
            # Test the range
            self.assertGreaterEqual(sn, minimum)
            self.assertLessEqual(sn, maximum)

    def test_loadkey(self):
        with self.assertRaises(FileNotFoundError):
            ca_create.load_key("dummy.key")

    def test_load_certificate(self):
        with self.assertRaises(FileNotFoundError):
            ca_create.load_certificate("dummy.cert")

    def test_load_csr(self):
        with self.assertRaises(FileNotFoundError):
            ca_create.load_csr("dummy.csr")

    def test_load_or_create(self):
        # Make a temp folder
        tempdir = tempfile.TemporaryDirectory()
        keyname = path.normpath(tempdir.name + "//test.key")
        # Create a key
        key = ca_create.load_or_create_key(keyname)
        # Load it back in
        key2 = ca_create.load_key(keyname)
        # Check that both return a key type
        self.assertEqual(type(key), type(key2))

    def test_generation(self):
        """
        Test creation of certificates from blank folder
        """
        tempfolder = tempfile.TemporaryDirectory()
        root_ca_key_path = path.normpath(tempfolder.name + "//root_ca.key")
        root_ca_cert_path = path.normpath(tempfolder.name + "//root_ca.cert")
        signer_ca_key_path = path.normpath(tempfolder.name + "//signer_ca.key")
        signer_ca_csr_path = path.normpath(tempfolder.name + "//signer_ca.csr")
        signer_csr_cert_path = path.normpath(tempfolder.name + "//csr.cert")

        # Create CA root and load it back to test
        ca_create.ca_create_root(root_ca_key_path, root_ca_cert_path)
        ca_create.load_key(root_ca_key_path)
        root_ca_cert = ca_create.load_certificate(root_ca_cert_path)

        # Create CA signer CSR and load it back to test
        ca_create.ca_create_signer_csr(signer_ca_key_path, signer_ca_csr_path)
        ca_create.load_key(signer_ca_key_path)
        # CSR will throw ValueError when attempting to load with this function
        with self.assertRaises(ValueError):
            ca_create.load_certificate(signer_ca_csr_path)

        # Create signer and load it back to test
        ca_create.ca_create_signer(signer_ca_csr_path, signer_csr_cert_path, root_ca_key_path, root_ca_cert_path)
        ca_signer_cert = ca_create.load_certificate(signer_csr_cert_path)

        # Finally validate the generated signer certificate using teh root certificate
        try:
            root_ca_cert.public_key().verify(ca_signer_cert.signature, ca_signer_cert.tbs_certificate_bytes,
                                             ECDSA(ca_signer_cert.signature_hash_algorithm))
        except crypto_exceptions.InvalidSignature:
            self.fail(msg="Verification of signer certificate failed")

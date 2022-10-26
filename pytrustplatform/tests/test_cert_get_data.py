"""
Unit tests for the cert_get_data module
"""
import os
import unittest
from pytrustplatform.cert_get_data import cert_get_skid, cert_get_common_name, create_cert_fingerprint
from pytrustplatform.tests.data import dummy_cert

TEST_CERT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'dummy_cert.crt')


class TestCertGetSkid(unittest.TestCase):
    """
    cert_get_skid unit tests
    """

    def test_cert_get_skid(self):
        skid = cert_get_skid(TEST_CERT_FILE)

        self.assertEqual(skid, dummy_cert.DUMMY_CERT_SKID)


class TestCertGetCommonName(unittest.TestCase):
    """
    cert_get_common_name unit tests
    """

    def test_get_common_name(self):
        cn = cert_get_common_name(TEST_CERT_FILE)

        self.assertEqual(cn, dummy_cert.DUMMY_CERT_COMMON_NAME)

class TestCreateCertFingerprint(unittest.TestCase):
    """
    create_cert_fingerprint unit tests
    """

    def test_create_cert_fingerprint(self):
        fp = create_cert_fingerprint(TEST_CERT_FILE)

        self.assertEqual(fp, dummy_cert.DUMMY_CERT_FINGERPRINT)

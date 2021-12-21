"""
Unit tests for manifest tool.
"""

import os
import sys
import unittest
import pathlib
from io import StringIO
from mock import patch
from pytrustplatform.cli_pytrust import main


DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output', 'manifest_tool_output')

MANIFEST_SIGNER_KEY = str(pathlib.Path(__file__).parent.absolute() / "data/dummy_signer-ca.key")
MANIFEST_SIGNER_CERT = str(pathlib.Path(__file__).parent.absolute() / "data/dummy_signer-ca.crt")
MANIFEST = str(pathlib.Path(__file__).parent.absolute() / "data/manifest_ATECC608A-MAH4I.json")
MANIFEST_SE_IDS = ["01230390b3d1450c01", "0123d26e26e688c901"]
MANIFEST_BUILD = str(pathlib.Path(OUTPUT_FOLDER) / "manifest.json")

DEVICE_CERTIFICATE = str(pathlib.Path(__file__).parent.absolute() / "../certs/ATECC608A-MAH4I/device_template.crt")
SIGNER_CERTIFICATE = str(pathlib.Path(__file__).parent.absolute() / "../certs/ATECC608A-MAH4I/signer_2C10.crt")

class TestManifestTool(unittest.TestCase):
    """Unit tests for functions in manifest module"""

    def setUp(self):
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

    def test_manifest_list_secure_element_ids(self):
        """Test list secure element ids
        Checks if the CLI list-secure-element-ids command lists the IDs of the secure elements
        that are in the manifest file.
        """
        testargs = ["pytrust", "manifest", "list-secure-element-ids", MANIFEST]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                #self.assertFalse(type(mock_stdout))
                self.assertTrue(MANIFEST_SE_IDS[0] in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertTrue(MANIFEST_SE_IDS[1] in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertEqual(retval, 0)

    def test_search_by_id(self):
        """Test search secure element by ID
        Checks if the CLI command 'get' returns the secure element referenced by --id from the manifest.
        """
        testargs = ["pytrust", "manifest", "get-secure-element", MANIFEST, '--id', MANIFEST_SE_IDS[0]]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue(MANIFEST_SE_IDS[0] in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertTrue("uniqueId" in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertEqual(retval, 0)

    def test_list_secure_elements(self):
        """Test list secure elements CLI command
        Verifies that the list-secure-elements CLI command returns all secure elements from the manifest.
        """
        testargs = ["pytrust", "manifest", "list-secure-elements", MANIFEST]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue(MANIFEST_SE_IDS[0] in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertTrue(MANIFEST_SE_IDS[1] in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertEqual(retval, 0)

    def test_get_certificates(self):
        """Test certificate extraction from manifest
        Verifies that the get-certificates CLI command extracts the certificates from a secure element in the manifest.
        """
        testargs = ["pytrust", "manifest", "get-certificates", MANIFEST, "--manifest-signer-cert",
                    MANIFEST_SIGNER_CERT, "--cert-index", "1,0", "--outdir", OUTPUT_FOLDER]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertTrue(MANIFEST_SE_IDS[0].upper() in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertTrue(MANIFEST_SE_IDS[1].upper() in mock_stdout.getvalue(),
                                msg=f"Actual stdout: {mock_stdout.getvalue()}")
                self.assertEqual(retval, 0)

    def test_create_from_certificates(self):
        """Test the manifest building from certificates
        Verifies that the create-from-certificates CLI command builds a manifest from certificates.
        """
        testargs = ["pytrust", "manifest", "create-from-certificates", MANIFEST_BUILD, "--manifest-signer-cert",
                    MANIFEST_SIGNER_CERT, "--manifest-signer-key", MANIFEST_SIGNER_KEY,
                    "--device-cert", DEVICE_CERTIFICATE, "--signer-cert", SIGNER_CERTIFICATE]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertEqual(retval, 0, msg=f"Actual stdout: {mock_stdout.getvalue()}")

    def test_create_from_certificates_with_type(self):
        """Test the manifest building from certificates with specifying a secure element type
        Verifies that the create-from-certificates CLI command builds a manifest from certificates.
        """
        testargs = ["pytrust", "manifest", "create-from-certificates", MANIFEST_BUILD, "--manifest-signer-cert",
                    MANIFEST_SIGNER_CERT, "--manifest-signer-key", MANIFEST_SIGNER_KEY,
                    "--device-cert", DEVICE_CERTIFICATE, "--signer-cert", SIGNER_CERTIFICATE, "--type", "TNGOTLS"]
        with patch.object(sys, 'argv', testargs):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                retval = main()
                self.assertEqual(retval, 0, msg=f"Actual stdout: {mock_stdout.getvalue()}")

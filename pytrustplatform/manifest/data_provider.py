"""Data providers for manifest building

The abstract class ManifestDataProvider describes an interface that the
manifest library uses to obtain secure element data to build a new entry
in a manifest.

Implementations of the ManifestDataProvider are e.g.
* EccDataProvider: Fetches data from a physical ECC device on supported tools.
* CertsData: Extracts data from device and signer certificates.
* EccTestData: Dummy test data provider.
"""
from datetime import datetime
import binascii
from logging import getLogger
from abc import ABC, abstractmethod
from base64 import b64encode
from serial import Serial
from pykitcommander.kitprotocols import setup_kit
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .manifest import TcustomTlsSecureElement, TnFlexTlsSecureElement, TnGoTlsSecureElement
from ..ecc_cert_builder import build_certs_from_ecc
from ..ecc_types import classify_ecc_type
from ..ca_create import load_certificate

class ManifestDataProvider(ABC):
    """ECC data provider abstract class.

    This class defines an interface that is used by the manifest library to
    build a SecureElement which then can be added to a manifest.
    Implementations of this class could be e.g. a dummy data provider for testing,
    a provider that gets ECC data via the Trust Platfrom development kit, or
    via any other development board.
    """
    @abstractmethod
    def get_serial_number(self):
        """Get the serial number of the crypto device

        :return: Serial number.
        :rtype: bytes
        """
        return bytearray("123aaafff")

    @abstractmethod
    def get_certificate(self, chain_index):
        """Provides the certificates for the manifest generation.

        :param chain_index: Position of the certificate in the chain e.g. 0=device certificate, 1=signer certificate
        :type chain_index: int
        :return: BASE64 encoded certificate or None
        :rtype: str
        """
        return

    @abstractmethod
    def get_pubkey(self, index):
        """Get public key.

        :param index: Key index of secure element.
        :type index: int
        :return: Public key. For EC keys raw X and Y coordinates e.g. 64 bytes for P256 curve coordinates
                 (uncompressed format but without first byte).
        :rtype: bytes
        """
        return bytearray(64)

class CertsData(ManifestDataProvider):
    """Data provider for manifest generation based on certificates.

    Extracts data from a device and signer certificate and provides this to
    the manifest builder as input.
    """
    def __init__(self, device_cert, signer_cert):
        """Class initialization

        :param device_cert: Device certificate file.
        :type device_cert: str
        :param signer_cert: Signer certificate file.
        :type signer_cert: str
        """
        self.device_cert = load_certificate(device_cert)
        self.signer_cert = load_certificate(signer_cert)
    def get_serial_number(self):
        """Provides secure element serial number

        :return: Serial number in hex encoded lower case letters.
        :rtype: str
        """
        serial = self.device_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if serial.startswith("sn"):
            serial = serial.lstrip("sn")
        return serial.lower()
    def get_provisioning_time(self):
        """Provides the provisioning time of the secure element.

        :return: Provisioning time is extracted from device certificate not-valid-before field.
        :rtype: datetime
        """
        return self.device_cert.not_valid_before

    def get_certificate(self, chain_index):
        """Provides the certificates for the manifest generation.

        :param chain_index: Position of the certificate in the chain e.g. 0=device certificate, 1=signer certificate
        :type chain_index: int
        :return: BASE64 encoded certificate or None
        :rtype: str
        """
        if chain_index == 0:
            b64_data = b64encode(self.device_cert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
        elif chain_index == 1:
            b64_data = b64encode(self.signer_cert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
        else:
            b64_data = None
        return b64_data
    def get_pubkey(self, index):
        """Provides the public key from the certificate.

        :param index: Index of the public key. Corresponds to the slot in ATECC608 secure element.
                      Since a certificate only contains the key from slot 0 we will only return a key
                      when the index is 0, otherwise None.
        :type index: int
        :return: Public key or None. For EC keys raw X and Y coordinates e.g. 64 bytes for P256 curve coordinates
                 (uncompressed format but without first byte).
        :rtype: bytes
        """
        if index == 0:
            key = self.device_cert.public_key()
            uncompressed_point = key.public_bytes(encoding=serialization.Encoding.X962,
                                              format=serialization.PublicFormat.UncompressedPoint)
            return uncompressed_point[1:]
        else:
            return None

class EccTestData(ManifestDataProvider):
    """Dummy data provider for testing.
    """
    def get_serial_number(self):
        """Dummy test serial number.

        :return: ECC serial number 9 bytes long
        :rtype: bytes
        """
        return bytearray.fromhex("01238CB07DCD507001")

    def get_provisioning_time(self):
        """Get secure element provisioning time.

        :return: Provisioning time.
        :rtype: datetime
        """
        return datetime.now()

    def get_certificate(self, chain_index):
        """Provides the certificates for the manifest generation.

        :param chain_index: Position of the certificate in the chain e.g. 0=device certificate, 1=signer certificate
        :type chain_index: int
        :return: BASE64 encoded certificate or None
        :rtype: str
        """
        if chain_index == 0:
            return """
MIIB8jCCAZegAwIBAgIQXCxnQEnEYHaVRrTG3g+PXzAKBggqhkjOPQQDAjBPMSEw
HwYDVQQKDBhNaWNyb2NoaXAgVGVjaG5vbG9neSBJbmMxKjAoBgNVBAMMIUNyeXB0
byBBdXRoZW50aWNhdGlvbiBTaWduZXIgRjYyMDAgFw0yMDExMTAxODAwMDBaGA8y
MDQ4MTExMDE4MDAwMFowQjEhMB8GA1UECgwYTWljcm9jaGlwIFRlY2hub2xvZ3kg
SW5jMR0wGwYDVQQDDBRzbjAxMjM4Q0IwN0RDRDUwNzAwMTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABFs1HerdbUhRcAUCg9mEYJJsA4GpRbxo5Q53rUVq629rtpDH
+XqMYMa2RzJo3IiXlMa4dmKYrtRkKotMvdZ5sj6jYDBeMAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgOIMB0GA1UdDgQWBBTVybQ7fI7IPXP+lDNNQ3Ic1slFcjAf
BgNVHSMEGDAWgBSbLiWBafb5r4wVkLQBhWFAbDx4VTAKBggqhkjOPQQDAgNJADBG
AiEAnzMrj25Y5Ru6zt/Welt0bO0/HDUhgMR+3pLhBRfVLJMCIQDeBTWT5XTAUFxi
+5SWo7EoPo3hdDqoL70msc+pFTAhEw==
"""
        if chain_index == 1:
            return """
MIICBDCCAaqgAwIBAgIQbzNq2drAQxFDPL993yUz1TAKBggqhkjOPQQDAjBPMSEw
HwYDVQQKDBhNaWNyb2NoaXAgVGVjaG5vbG9neSBJbmMxKjAoBgNVBAMMIUNyeXB0
byBBdXRoZW50aWNhdGlvbiBSb290IENBIDAwMjAgFw0xODEyMTQxOTAwMDBaGA8y
MDQ5MTIxNDE5MDAwMFowTzEhMB8GA1UECgwYTWljcm9jaGlwIFRlY2hub2xvZ3kg
SW5jMSowKAYDVQQDDCFDcnlwdG8gQXV0aGVudGljYXRpb24gU2lnbmVyIEY2MjAw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT7abedJjzHJibzpDH/a1NCD2LVUvHQ
+WeFX7QtfcrW7MSShFWPSMqkSnIlS5WaYjJWdU6s7hPSAZ9jdFqejJfko2YwZDAO
BgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUmy4l
gWn2+a+MFZC0AYVhQGw8eFUwHwYDVR0jBBgwFoAUeu19bca3eJ2yOAGl6EqMsKQO
KowwCgYIKoZIzj0EAwIDSAAwRQIgRJPgU4g6ZZ1+TCL89rW0+HNaUIJ/n5q08Rqb
cn92R98CIQCGYpyiFYwWRb0Pg4wu8zLQk0O1/W/oJBxkxHAD5v3XGw==
"""
        return None

    def get_pubkey(self, index):
        """Dummy public key.

        :param slot: Key index.
        :type slot: int
        :return: Public key, 64 bytes.
        :rtype: bytes
        """
        return bytearray().fromhex("49341da54eca0c6c7de66d12ae651b3750d624218b678502b8632b2c9561ac81")

    def get_secure_element(self):
        """Get the secure element

        :return: Secure element instance
        :rtype: Subclass of SecureElement e.g. TnGoTlsSecureElement, TnFlexTlsSecureElement ...
        """
        secure_element = TnFlexTlsSecureElement()

        return secure_element.build(self)

class EccDataProvider(ManifestDataProvider):
    """Provides secure element data from ECC devices
    """
    def __init__(self):
        self.device_cert = None
        self.signer_cert = None
        self.serial_connection = None
        self.logger = getLogger(__name__)
        # Fetch a protocol object from pykitcommander
        info = setup_kit('iotprovision')

        # Collect required info to continue:
        port = info['port']
        baud = info['protocol_baud']
        protocol = info['protocol_class']

        self.serial_connection = Serial(port=port, baudrate=baud)
        self.firmware_driver = protocol(self.serial_connection)
        self.firmware_driver.synchronize()             # Make sure communication is synchronized
        self.ecc_type = self._detect_secure_element_type()

    def __del__(self):
        if self.serial_connection:
            self.serial_connection.close()

    def get_serial_number(self):
        """Provides secure element serial number

        :return: Serial number in hex encoded lower case letters.
        :rtype: str
        """
        serial = self.firmware_driver.firmware_command("MC+ECC+SERIAL")
        return serial.lower()

    def get_provisioning_time(self):
        """Provides the provisioning time of the secure element.

        :return: Provisioning time is extracted from device certificate not-valid-before field.
        :rtype: datetime
        """
        if not self.device_cert:
            self._load_certificates()
        return self.device_cert.not_valid_before

    def get_certificate(self, chain_index):
        """Provides the certificates for the manifest generation.

        :param chain_index: Position of the certificate in the chain e.g. 0=device certificate, 1=signer certificate
        :type chain_index: int
        :return: BASE64 encoded certificate or None
        :rtype: str
        """
        if not self.device_cert:
            self._load_certificates()

        if chain_index == 0:
            b64_data = b64encode(self.device_cert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
        elif chain_index == 1:
            b64_data = b64encode(self.signer_cert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
        else:
            b64_data = None
        return b64_data

    def get_pubkey(self, index):
        """Get public key.

        :param index: Key index of secure element.
        :type index: int
        :return: Public key. For EC keys raw X and Y coordinates e.g. 64 bytes for P256 curve coordinates
                 (uncompressed format but without first byte).
        :rtype: bytes
        """
        try:
            key = binascii.a2b_hex(self.firmware_driver.firmware_command("MC+ECC+GENPUBKEY", [f"{index}"]))
            assert len(key) == 64
        except Exception:
            self.logger.error("Could not generate public key from slot %i.", index)
            return None
        return key

    def get_secure_element(self):
        """Get the secure element

        :return: Secure element instance
        :rtype: Subclass of SecureElement e.g. TnGoTlsSecureElement, TnFlexTlsSecureElement ...
        """
        if len(self.ecc_type) == 1:
            if self.ecc_type[0] == "tng":
                secure_element = TnGoTlsSecureElement()
            elif self.ecc_type[0] in ("tflx", "mah4i"):
                secure_element = TnFlexTlsSecureElement()
            elif self.ecc_type[0] == "mah1h":
                secure_element = TcustomTlsSecureElement()
            else:
                self.logger.warning("Secure element type '%s' not implemented", self.ecc_type)
                self.logger.warning("Using secure element type 'tng' (trust & go) instead")
                secure_element = TnGoTlsSecureElement()
        else:
            self.logger.warning("Secure element type could be '%s'", self.ecc_type)
            self.logger.warning("Using secure element type 'tng' (trust & go)")
            secure_element = TnGoTlsSecureElement()
        secure_element.build(self)
        return secure_element

    def _load_certificates(self):
        """Build certificates from ECC content
        """
        self.device_cert, self.signer_cert = build_certs_from_ecc(self.firmware_driver)

    def _detect_secure_element_type(self):
        """Determine secure element type

        :return: List of possible matches e.g. ("tngo", "tflx")
        :rtype: list
        """
        serial = self.firmware_driver.firmware_command("MC+ECC+SERIAL")
        try:
            otp_values = self.firmware_driver.firmware_command("MC+ECC+OTP+READ", ["8"])
        except Exception:
            ecc_type = classify_ecc_type(serial)
        else:
            ecc_type = classify_ecc_type(serial, otp_values)
        return ecc_type

"""
Decodes compressed certificates from ECC
"""
import hashlib
import binascii

from datetime import datetime, timezone
from logging import getLogger

#pylint: disable=wrong-import-position
# This module uses pykitcommander:
# Functions in this module make use of the pykitcommander package to:
# - program application firmware on to the MCU based on the APPLICATION
# - handle protocol framing according to the firmware driver
APPLICATION = "iotprovision"
APPLICATION_PROTOCOL_ID = "ProvisioningV2"

from .serialnumber import new_publickey_serialnumber
from .serialnumber import new_device_serialnumber


TEST_TEMPLATE_ID = 0
TEST_CHAIN_ID = 0
TEST_SN_SOURCE = 0
TEST_FORMAT_VERSION = 0
TEST_DATE_YEAR = 5
TEST_DATE_MONTH = 1
TEST_DATE_DAY = 1
TEST_DATE_HOUR = 1
TEST_DATE_EXPIRE_YEAR = 20

test_data = bytearray(64)
test_data += (TEST_DATE_YEAR << 19 | TEST_DATE_MONTH << 15 | TEST_DATE_DAY << 10 |
              TEST_DATE_HOUR << 5 | TEST_DATE_EXPIRE_YEAR).to_bytes(3, byteorder="big", signed=False)
test_data += bytes([TEST_TEMPLATE_ID << 4 | TEST_CHAIN_ID])
test_data += bytes([TEST_SN_SOURCE << 4 | TEST_FORMAT_VERSION])
test_data += bytearray(2)

"""
.. module:: compressed_data

Element      |Size(bits)|Description
---------------------------------------------------------------------
Signature      512       Certificate signature stored as the 32 byte R and S unsigned big-endian integers.
Encoded Dates  24        Certificate issue and expiration dates in a bit-packed format.
Signer ID      16        ID of the specific signer used to sign the certificate (device cert)
                         or of the signer itself (signer cert).
Template ID     4        ID of the certificate template to be used to reconstruct the full X.509 certificate.
Chain ID        4        ID of the certificate chain being used.
SN Source       4        Indicates where to find or how to generate the certificate serial number.
Format Version  4        Version of the compressed certificate format. 0 is the only version.
Reserved        8        Reserved byte


Compressed Certificate

Non pythonic slice notation
Signature[0:63]
Encoded Dates[64:66]
Signer ID[67:68]
Template ID[69] upper nibble
Chain ID[69] lower nibble
SN source[70] upper nibble
Format version[70] lower nibble
Reserved[71]
"""

class CertificateRepresentation():
    """
    Representation of a certificate
    """
    def __init__(self, compressed_certificate_data):
        self.logger = getLogger(__name__)
        self.compressed_certificate = None
        self.compressed_certificate_data = compressed_certificate_data
        self.validity_not_before = None
        self.validity_not_after = None
        self.signer_id = None
        self.signature = None
        self.chain_id = None
        self.module_id = None
        self.ecc_id = None
        self.slot_id = None
        self.template_id = None
        self.chain_id = None
        self.sn_source = None
        self.sn_number = None
        self.format_version = None
        self.pkey = None
        self.eui48 = None

    def _decode_common(self, compressed_certificate):
        """
        Decodes common parts of a certificate
        :param compressed_certificate: compressed representation
        """
        self.compressed_certificate = compressed_certificate
        self._decode_signature()
        self._decode_dates()
        self._decode_signer_id()
        self._decode_template_id()
        self._decode_chain_id()
        self._decode_sn_source()
        self._decode_format_version()
        self.log()

    def log(self):
        """
        Log some fields
        """
        self.logger.debug("Signature:      %s", self.signature)
        self.logger.debug("Issue date:     %s", self.validity_not_before)
        self.logger.debug("Expire date:    %s", self.validity_not_after)
        self.logger.debug("Signer ID:      %s", hex(self.signer_id))
        self.logger.debug("Template ID:    %s", self.template_id)
        self.logger.debug("Chain ID:       %s", self.chain_id)
        self.logger.debug("SN source:      %s", self.sn_source)
        self.logger.debug("Format version: %s", self.format_version)

    def _decode_signature(self):
        """ Decode signature field """
        self.signature = self.compressed_certificate[:64]

    def _decode_dates(self):
        """ Decode date fields """
        tmp = int.from_bytes(self.compressed_certificate[64:67], signed=False, byteorder='big')
        year = (tmp >> 19 & 0x1F) + 2000
        month = tmp >> 15 & 0x0F
        day = tmp >> 10 & 0x1F
        hour = tmp >> 5 & 0x1F
        expire_years = tmp & 0x1F

        if expire_years == 0:
            expire_year = 9999
            self.validity_not_after = datetime(expire_year, 12, 31, 23, 59, 59).replace(tzinfo=timezone.utc)
        else:
            expire_year = expire_years + year
            self.validity_not_after = datetime(expire_year, month, day, hour).replace(tzinfo=timezone.utc)
        # Note: UTC is the default timezone so no need to specify this explicitly
        self.validity_not_before = datetime(year, month, day, hour).replace(tzinfo=timezone.utc)

    def _decode_signer_id(self):
        """ Decode signer ID field """
        self.signer_id = int.from_bytes(self.compressed_certificate[67:69], signed=False, byteorder='big')
        self.module_id = self.signer_id >> 8 & 0x00FF
        self.ecc_id = self.signer_id >> 4 & 0x000F
        self.slot_id = self.signer_id & 0x000F

    def _decode_template_id(self):
        """ Decode template ID field """
        self.template_id = (self.compressed_certificate[69] & 0xF0) >> 4

    def _decode_chain_id(self):
        """ Decode chain ID field """
        self.chain_id = self.compressed_certificate[69] & 0x0F

    def _decode_sn_source(self):
        """ Decode serial number source field """
        self.sn_source = (self.compressed_certificate[70] & 0xF0) >> 4

    def _decode_format_version(self):
        """ Decode format version field """
        self.format_version = self.compressed_certificate[70] & 0x0F
        # Currently only one version implemented
        assert self.format_version == 0

    def build_serialnumber(self, pubkey=None, dev_sn_number=None):
        """
        Builds a serial number
        :param pubkey: public key to use
        :param dev_sn_number: serial number to use
        """
        if self.sn_source == 0:
            raise Exception("Serial number generation from stored serial number not implemented.")
        if self.sn_source == 0xA: # Generate from pubkey
            self.sn_number = new_publickey_serialnumber(pubkey, not_valid_before=self.validity_not_before,
                                                        not_valid_after=self.validity_not_after)
        elif self.sn_source == 0xB: # Generate from device serial number
            self.sn_number = new_device_serialnumber(dev_sn_number, not_valid_before=self.validity_not_before,
                                                     not_valid_after=self.validity_not_after)
        else:
            raise Exception("{} is not valid serial number source".format(self.sn_source))

class DeviceCertificateRepresentation(CertificateRepresentation):
    """
    Representation of a device certificate
    """
    def __init__(self, compressed_certificate_data):
        CertificateRepresentation.__init__(self, compressed_certificate_data)
        self.logger = getLogger(__name__)
        self.device_pkey = compressed_certificate_data.device_pkey
        self._decode_common(compressed_certificate_data.compressed_device_cert)
        self.build_serialnumber(pubkey=self.compressed_certificate_data.device_pkey)
        self.ecc_serial_number = self.compressed_certificate_data.ecc_serial_number
        self.akid = create_key_identifier(self.compressed_certificate_data.signer_pkey)
        self.skid = create_key_identifier(self.compressed_certificate_data.device_pkey)

class SignerCertificateRepresentation(CertificateRepresentation):
    """
    Representation of a signer certificate
    """
    def __init__(self, compressed_certificate_data):
        CertificateRepresentation.__init__(self, compressed_certificate_data)
        self.logger = getLogger(__name__)
        self.compressed_certificate_data = compressed_certificate_data
        self.signer_pkey = compressed_certificate_data.signer_pkey
        self._decode_common(compressed_certificate_data.compressed_signer_cert)
        self.build_serialnumber(pubkey=self.compressed_certificate_data.signer_pkey)
        self.skid = create_key_identifier(self.compressed_certificate_data.signer_pkey)

def create_key_identifier(pubkey):
    """
    Create the key identifier.

    :param bytearray pubkey: Public key from which the key identifier should be derived.
    :type pubkey: bytearray
    """
    tmp = b"\x04" + pubkey
    key_identifier = hashlib.sha1(tmp).digest()
    return key_identifier



class CompressedCertificateData():
    """
    Compressed certificate data provider
    """
    def __init__(self):
        self.logger = getLogger(__name__)
        self.ecc_serial_number = None
        self.compressed_signer_cert = None
        self.compressed_device_cert = None
        self.device_pkey = None
        self.signer_pkey = None
        self.device_eui48 = None

    def read_from_kit(self, firmware_driver):
        """
        Read data from a kit
        Do not read slot 5 - see function read_from_kit_slot5

        :param firmware_driver: Protocol driver instance for communicating with firmware on the MCU
        """
        self.logger.info("Reading data from ECC device")
        # The firmware driver wraps a serial port connection which enables a simple command-response transaction
        # This driver structure is defined in pykitcommander.firmwareinterface

        # Send firmware command to read the ECC serial number
        self.ecc_serial_number = binascii.a2b_hex(firmware_driver.firmware_command("MC+ECC+SERIAL"))
        self.logger.debug(binascii.b2a_hex(self.ecc_serial_number))

        # Send firmware command to read the ECC slot 12
        self.compressed_signer_cert = binascii.a2b_hex(firmware_driver.firmware_command("MC+ECC+READ", ["12", "72"]))
        self.logger.debug(binascii.b2a_hex(self.compressed_signer_cert))

        # Send firmware command to read the ECC slot 10
        self.compressed_device_cert = binascii.a2b_hex(firmware_driver.firmware_command("MC+ECC+READ", ["10", "72"]))
        self.logger.debug(binascii.b2a_hex(self.compressed_device_cert))

        # Send firmware command to read the public key
        self.device_pkey = binascii.a2b_hex(firmware_driver.firmware_command("MC+ECC+GENPUBKEY"))
        self.logger.debug(binascii.b2a_hex(self.device_pkey))

        # Send firmware command to read the ECC slot 11
        padded_signer_key = binascii.a2b_hex(firmware_driver.firmware_command("MC+ECC+READ", ["11", "72"]))
        self.logger.debug(binascii.b2a_hex(padded_signer_key))
        self.signer_pkey = padded_signer_key[4:36] + padded_signer_key[36+4:]

    def read_from_kit_slot5(self, firmware_driver):
        """
        Read slot 5 data from a kit
        Slot 5 is only readable if the ECC is not in [MAH1H, MAH4I]

        :param firmware_driver: Protocol driver instance for communicating with firmware on the MCU
        """
        self.logger.info("Reading slot 5 from ECC device")
        # The firmware driver wraps a serial port connection which enables a simple command-response transaction
        # This driver structure is defined in pykitcommander.firmwareinterface

        # Send firmware command to read the ECC slot 5
        self.device_eui48 = firmware_driver.firmware_command("MC+ECC+READ", ["5", "36"])[:12]
        self.logger.debug(self.device_eui48)

"""
serial number utility functions
"""

import hashlib
from os import urandom


def _format_serialnumber(raw, enforce_positive_non_trimmable=True):
    if enforce_positive_non_trimmable:
        raw[0] &= 0x7F # Force MSB bit to 0 to ensure positive integer
        raw[0] |= 0x40 # Force next bit to 1 to ensure the integer won't be trimmed in ASN.1 DER encoding
    return int.from_bytes(raw, byteorder='big', signed=False)

def _encode_dates(not_valid_before, not_valid_after):
    """
    Encode dates into compressed certificate format.

    :param datetime not_valid_before: Certificate not valid before date.
    :param datetime not_valid_after: Certificate not valid after date.
    :returns bytearray: Compressed certificate dates format (3 bytes)
    """
    expire_years = not_valid_after.year - not_valid_before.year
    if not_valid_after.year == 9999:
        expire_years = 0 # This year is used when indicating no expiration
    elif expire_years > 31:
        expire_years = 1 # We default to 1 when using a static expire beyond 31

    enc_dates = bytearray(b'\x00'*3)
    enc_dates[0] = (enc_dates[0] & 0x07) | ((((not_valid_before.year - 2000) & 0x1F) << 3) & 0xFF)
    enc_dates[0] = (enc_dates[0] & 0xF8) | ((((not_valid_before.month) & 0x0F) >> 1) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x7F) | ((((not_valid_before.month) & 0x0F) << 7) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x83) | (((not_valid_before.day & 0x1F) << 2) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0xFC) | (((not_valid_before.hour & 0x1F) >> 3) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0x1F) | (((not_valid_before.hour & 0x1F) << 5) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0xE0) | ((expire_years & 0x1F) & 0xFF)
    enc_dates = bytes(enc_dates)

    return enc_dates


def new_random_serialnumber(size=16):
    """
    Create a positive, non-trimmable serial number for X.509 certificates

    :param int size: Size of the serial number max 32. 16 is used for ECC608 certificates.
    """
    raw_sn = bytearray(urandom(size))
    return _format_serialnumber(raw_sn)

def new_publickey_serialnumber(pubkey, size=16, not_valid_before=None, not_valid_after=None, enc_dates=None):
    """
    Create serial number from SHA256(Subject public key + Encoded dates)

    Takes either not_valid_before and not_valid_after, or raw enc_dates. If both are provided the
    dates will have preference.

    :param int size: Size of the serial number max 32. 16 is used for ECC608 certificates.
    :param datetime not_valid_before: Certificate not valid before date.
    :param datetime not_valid_after: Certificate not valid after date.
    :param bytearray enc_dates: Encoded dates from compressed certificate (3 bytes)
    """

    if not_valid_before and not_valid_after:
        enc_dates = _encode_dates(not_valid_before, not_valid_after)

    if enc_dates is None:
        raise Exception("Dates must be given to generate serialnumber")

    # SAH256 hash of the public key and encoded dates
    sn_number = bytearray(hashlib.sha256(pubkey + enc_dates).digest()[:size])
    return _format_serialnumber(sn_number)

def new_device_serialnumber(device_serial_number, size=16, not_valid_before=None, not_valid_after=None, enc_dates=None):
    """
    Creates serial number from SHA256(device SN [9 bytes] + encoded dates [3 bytes])

    Takes either not_valid_before and not_valid_after, or raw enc_dates. If both are provided the
    dates will have preference.

    :param int size: Size of the serial number max 32. 16 is used for ECC608 certificates.
    :param datetime not_valid_before: Certificate not valid before date.
    :param datetime not_valid_after: Certificate not valid after date.
    :param bytearray enc_dates: Encoded dates from compressed certificate (3 bytes)
    """

    sn_number = bytearray(hashlib.sha256(device_serial_number + enc_dates).digest()[:size])
    return _format_serialnumber(sn_number)

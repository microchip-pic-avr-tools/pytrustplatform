
"""
ECC (Elliptic Curve Cryptography) conversions
"""

from binascii import b2a_hex
from logging import getLogger

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives import serialization

# A prefix of 0x04 means uncompressed point (DER format)
UNCOMPRESSED_KEY_PREFIX = b"\x04"

def get_pubkey_PEM_format_from_raw_xy_point (raw_xy_point):
    """Conversion from raw xy point to public key in PEM format

    :param raw_xy_point, uncompressed point
    :type binary data, bytes
    :return public key in PEM format
    """
    logger = getLogger(__name__)
    uncompressed_point = UNCOMPRESSED_KEY_PREFIX + raw_xy_point
    pubkey = EllipticCurvePublicKey.from_encoded_point(SECP256R1(),uncompressed_point)
    serialized_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    logger.debug("Public key, PEM format: %s",serialized_pem)

    return serialized_pem

def get_raw_xy_point_from_pubkey_PEM_format(public_key):
    """Conversion from public key in PEM format to raw x y point

    :param  Public key in PEM format
    :type str
    :return binary data, bytes
    :Raises ValueError if public key is not type Elliptic Curve
    """
    logger = getLogger(__name__)
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise ValueError("provided public key must be of type Elliptic Curve")
    uncompressed_point = public_key.public_bytes(encoding=serialization.Encoding.X962,
                                                 format=serialization.PublicFormat.UncompressedPoint)
    #remove prefix
    raw_xy_point = uncompressed_point[1:]
    logger.debug("Public key, raw xy point format: '%s'", b2a_hex(raw_xy_point))

    return raw_xy_point

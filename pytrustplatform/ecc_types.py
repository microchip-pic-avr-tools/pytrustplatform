"""
Helper for differentiating between various types of ECC devices
"""
from logging import getLogger

# Serial number suffix for custom ECC608 devices
ECC608_CUSTOM_SERIAL_SUFFIX = "FE"
# Serial number suffix for Trust&Go and Trust&Flex based ECC608 devices
ECC608_TFLX_TNG_SERIAL_SUFFIX = "01"

# OTP content differentiators for known ECC variants
OTP_MAH4I = "4D4B4D7779685031"
OTP_TNG = "7836746A755A4D79"
OTP_MAH1H = "FFFFFFFFFFFFFFFF"

# String identifiers used
ECC_MAH1H = 'mah1h'
ECC_MAH4I = 'mah4i'
ECC_TNG = 'tng'
ECC_TFLX = 'tflx'
ECC_CUSTOM = 'custom'
ECC_UNKNOWN = 'unknown'

def classify_ecc_type (ecc_serial_number, ecc_otp_values=None):
    """
    Classifies the ECC type based on input parameters, returning a list of likely matches.
    Possible types to classify:
    Trust&Go: 'tng'
    Trust&Flex: 'tflx'
    Trust custom: 'custom'
    MAH4I: 'mah4i'
    MAH1H: 'mah1h'

    :param ecc_serial_number: serial number read from the ECC
    :param ecc_otp_values: optional OTP area contents
    :returns: a list of likely matches
    """
    logger = getLogger(__name__)

    ecc_types = []
    # First classify by serial number suffix
    suffix = ecc_serial_number[-2:].upper()
    if suffix == ECC608_CUSTOM_SERIAL_SUFFIX:
        # Narrow down based on OTP area content
        if ecc_otp_values:
            if ecc_otp_values == OTP_MAH1H:
                ecc_types.append(ECC_MAH1H)
            else:
                ecc_types.append(ECC_CUSTOM)
        else:
            ecc_types.append(ECC_MAH1H)
            ecc_types.append(ECC_CUSTOM)
    elif suffix == ECC608_TFLX_TNG_SERIAL_SUFFIX:
        # Narrow down based on OTP area content
        if ecc_otp_values:
            if ecc_otp_values == OTP_TNG:
                ecc_types.append(ECC_TNG)
            elif ecc_otp_values == OTP_MAH4I:
                ecc_types.append(ECC_MAH4I)
            else:
                ecc_types.append(ECC_TFLX)
        else:
            ecc_types.append(ECC_MAH4I)
            ecc_types.append(ECC_TFLX)
            ecc_types.append(ECC_TNG)
    else:
        ecc_types.append(ECC_UNKNOWN)
    logger.debug("ECC type(s): %s", ecc_types)
    return ecc_types

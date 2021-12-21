"""
Entry point for certificate command of pytrust CLI
"""
import os.path
from logging import getLogger

from pyedbglib.serialport.serialcdc import SerialCDC

# This module uses pykitcommander:
# Functions in this module make use of the pykitcommander package to:
# - program application firmware on to the MCU based on the APPLICATION
# - handle protocol framing according to the firmware driver
from pykitcommander.kitprotocols import setup_kit
from pykitcommander.firmwareinterface import KitCommunicationError
from serial.serialutil import SerialException

#pylint: disable=relative-beyond-top-level
from .ecc_cert_builder import build_certs_from_ecc
from .cert_get_data import cert_get_skid, create_cert_fingerprint, cert_get_common_name
from .device_cert_builder import build_device_cert
from .verification_cert_builder import build_verification_cert
from .status_codes import STATUS_SUCCESS, STATUS_FAILURE
from .ecc_types import classify_ecc_type

from .ca_create import ca_create_root
from .ca_create import ca_create_signer_csr
from .ca_create import ca_create_signer

ROOT_CA_FILENAME_BASE = 'root-ca'
ROOT_CA_KEY_FILENAME = ROOT_CA_FILENAME_BASE + '.key'
ROOT_CA_CERT_FILENAME = ROOT_CA_FILENAME_BASE + '.crt'

SIGNER_CA_FILENAME_BASE = 'signer-ca'
SIGNER_CA_KEY_FILENAME = SIGNER_CA_FILENAME_BASE + '.key'
SIGNER_CA_CSR_FILENAME = SIGNER_CA_FILENAME_BASE + '.csr'
SIGNER_CA_CERT_FILENAME = SIGNER_CA_FILENAME_BASE + '.crt'
SIGNER_CA_VER_CERT_FILENAME = SIGNER_CA_FILENAME_BASE + '-verification.crt'

DEVICE_FILENAME_BASE = 'device'
DEVICE_CSR_FILENAME = DEVICE_FILENAME_BASE + '.csr'
DEVICE_CERT_FILENAME = DEVICE_FILENAME_BASE + '.crt'

def certificate_cli_handler(args):
    """
    Entry point for certificate command of CLI
    """
    logger = getLogger(__name__)
    if args.action == "create-from-ecc":
        return _action_create_from_ecc(args)

    if args.action == "create-chain-of-trust":
        logger.info("Creating chain of trust")

        # Generate output
        output_path = args.output_path
        if output_path is None:
            output_path = '.'
        else:
            if not os.path.isdir(output_path):
                logger.info("Create Output folder '%s'", output_path)
                os.mkdir(output_path)

        # generate filename with full path
        root_key_filename = os.path.join(output_path, ROOT_CA_KEY_FILENAME)
        root_cert_filename = os.path.join(output_path, ROOT_CA_CERT_FILENAME)
        signer_key_filename = os.path.join(output_path, SIGNER_CA_KEY_FILENAME)
        signer_csr_filename = os.path.join(output_path, SIGNER_CA_CSR_FILENAME)
        signer_cert_filename = os.path.join(output_path, SIGNER_CA_CERT_FILENAME)

        # Create Root
        ca_create_root(root_ca_key_path=root_key_filename,
                       root_ca_cert_path=root_cert_filename, force=args.force,
                       org_name=args.organization_name, common_name=args.root_common_name)

        # Create signer CSR
        ca_create_signer_csr(signer_ca_key_path=signer_key_filename,
                             signer_ca_csr_path=signer_csr_filename, force=args.force,
                             org_name=args.organization_name, common_name=args.signer_common_name)

        # Create signer
        ca_create_signer(signer_ca_csr_path=signer_csr_filename,
                         signer_ca_cert_path=signer_cert_filename,
                         root_ca_key_path=root_key_filename,
                         root_ca_cert_path=root_cert_filename, force=args.force)

    if args.action == "read-ecc-serialnumber" or args.action == "read-ecc-type":
        # Reading the serial number from the ECC is done via an application running on the MCU
        # which communicates with this utility over a standard serial port.

        # Program the "provisioning" firmware into the MCU using pykitcommander's helper function
        # (To program custom firmware, make use of the KitProgrammer class directly)
        info = setup_kit("iotprovision", skip_programming=args.skip_target_programming, serialnumber=args.serialnumber)

        # The kit is now programmed, and the info dict contains all the information we need to proceed

        # Create a serial connection to communicate with the firmware
        # Note: SerialCDC class wraps pyserial Serial class
        try:
            with SerialCDC(info['port'], info['protocol_baud'], timeout=10, stopbits=2) as serial_connection:
                # The firmware driver wraps a serial port connection which enables a simple command-response transaction
                # This driver structure is defined in pykitcommander.firmwareinterface
                firmware_driver = info['protocol_class'](serial_connection)
                # Make sure communication is synchronized
                firmware_driver.synchronize()

                error_led = info['kit_info']['leds'].ERROR_LED
                connection_led = info['kit_info']['leds'].CONNECTION_LED
                # Switch off error LED in case it was lit due to previous failure
                firmware_driver.firmware_command("MC+SETLED", [error_led,"off"])
                # Turn on connection LED to indicate communication with target
                firmware_driver.firmware_command("MC+SETLED", [connection_led,"on"])
                try:
                    logger.info("Requesting ECC serial number from kit firmware...")
                    # Send firmware command to read the ECC serial number
                    ecc_serial_number = firmware_driver.firmware_command("MC+ECC+SERIAL")
                except KitCommunicationError as error:
                    logger.error("Read ECC serial number failed with %s: %s", type(error).__name__, error)
                    logger.debug(error, exc_info=True)    # get traceback if debug loglevel
                    # Signal error by turning on ERROR LED
                    firmware_driver.firmware_command("MC+SETLED", [error_led,"on"])
                    # Make sure connection LED is switched off before returning
                    firmware_driver.firmware_command("MC+SETLED", [connection_led,"off"])
                    return STATUS_FAILURE

                print("ECC serial number read: '{}'".format(ecc_serial_number))

                # More details for read-ecc-type
                if args.action == "read-ecc-type":
                    logger.info("Requesting ECC OTP area from kit firmware...")
                    otp_values = firmware_driver.firmware_command("MC+ECC+OTP+READ", ["8"])
                    ecc_type = classify_ecc_type(ecc_serial_number, otp_values)
                    print("ECC type read: '{}'".format(",".join(ecc_type)))

                # Send firmware command to turn LED off
                firmware_driver.firmware_command("MC+SETLED", [connection_led,"off"])
        except SerialException as exc:
            print("Unable to open port '{}'. Check that the port is not in use, or specify an alternative port."
                .format(info['port']))
            logger.debug(exc, exc_info=True)    # get traceback if debug loglevel
            return STATUS_FAILURE

    if args.action == "fingerprint":
        logger.info("Creating fingerprint of the certificate")

        fingerprint = create_cert_fingerprint(args.certificate_file)
        print("fingerprint: {}".format(fingerprint))

    if args.action == "get-skid":
        skid = cert_get_skid(args.certificate_file)
        print("Subject Key Identifier (hex): {}".format(skid))
        print("Subject Key Identifier Length: {}".format(len(skid)))

    if args.action == "get-common-name":
        print("Common Name: {}".format(cert_get_common_name(args.certificate_file)))

    if args.action == "create-from-csr":
        return _action_create_from_csr(args)

    if args.action == "create-verification":
        return _action_create_verification(args)

    return STATUS_SUCCESS

def _action_create_from_csr(args):
    """Create Device certificate from CSR (Certificate Signing Request)

    This action will first create a CSR based on a public key read from the target ECC device and then use this CSR to
    create a device certificate.  Both the generated CSR and the certificate will be written to file.
    :param args: command line arguments
    :type args: class:`argparse.Namespace`
    :return: Status code (STATUS_SUCCESS or STATUS_FAILURE)
    :rtype: int
    """
    logger = getLogger(__name__)

    output_path = _create_output_folder(args)

    csr_filename = os.path.join(output_path, "device.csr")
    cert_filename = os.path.join(output_path, "device.crt")

    # Creating the device certificate from the CSR is done via an application running on the MCU
    # which communicates with this utility over a standard serial port.

    # Program the "provisioning" firmware into the MCU using pykitcommander's helper function
    # (To program custom firmware, make use of the KitProgrammer class directly)
    info = setup_kit("iotprovision", skip_programming=args.skip_target_programming, serialnumber=args.serialnumber)
    # The kit is now programmed, and the info dict contains all the information we need to proceed

    # Create a serial connection to communicate with the firmware
    # Note: SerialCDC class wraps pyserial Serial class
    try:
        with SerialCDC(info['port'], info['protocol_baud'], timeout=10, stopbits=2) as serial_connection:
            # The firmware driver wraps a serial port connection which enables a simple command-response transaction
            # This driver structure is defined in pykitcommander.firmwareinterface
            firmware_driver = info['protocol_class'](serial_connection)
            # Make sure communication is synchronized
            firmware_driver.synchronize()

            error_led = info['kit_info']['leds'].ERROR_LED
            connection_led = info['kit_info']['leds'].CONNECTION_LED
            # Switch off error LED in case it was lit due to previous failure
            firmware_driver.firmware_command("MC+SETLED", [error_led,"off"])
            # Turn on connection LED to indicate communication with target
            firmware_driver.firmware_command("MC+SETLED", [connection_led,"on"])
            try:
                # Now build the certificates
                logger.info("Building certificates using information from firmware...")
                build_device_cert(firmware_driver,
                                args.signer_ca_certificate_file,
                                args.signer_ca_key_file,
                                csr_filename,
                                cert_filename,
                                force=args.force)
            except KitCommunicationError as error:
                logger.error(error)
                # Signal error by turning on ERROR LED
                firmware_driver.firmware_command("MC+SETLED", [error_led,"on"])
                # Make sure connection LED is switched off before returning
                firmware_driver.firmware_command("MC+SETLED", [connection_led,"off"])
                return STATUS_FAILURE

            # Send firmware command to turn LED off
            firmware_driver.firmware_command("MC+SETLED", [connection_led,"off"])
            return STATUS_SUCCESS
    except SerialException as exc:
        print("Unable to open port '{}'. Check that the port is not in use, or specify an alternative port."
            .format(info['port']))
        logger.debug(exc, exc_info=True)    # get traceback if debug loglevel
        return STATUS_FAILURE

def _action_create_from_ecc(args):
    """Create Device certificate and Signer certificate using compressed data read from ECC device

    Both certificates will be written to file
    :param args: command line arguments
    :type args: class:`argparse.Namespace`
    :return: Status code (STATUS_SUCCESS or STATUS_FAILURE)
    :rtype: int
    """
    logger = getLogger(__name__)
    output_path = _create_output_folder(args)

    device_cert_filename = os.path.join(output_path, "device_ecc608.crt")
    signer_cert_filename = os.path.join(output_path, "signer_ecc608.crt")

    # Creating the certificate from the ECC is done via an application running on the MCU
    # which communicates with this utility over a standard serial port.

    # Program the "provisioning" firmware into the MCU using pykitcommander's helper function
    # (To program custom firmware, make use of the KitProgrammer class directly)
    info = setup_kit("iotprovision", skip_programming=args.skip_target_programming, serialnumber=args.serialnumber)
    # The kit is now programmed, and the info dict contains all the information we need to proceed

    # Create a serial connection to communicate with the firmware
    # Note: SerialCDC class wraps pyserial Serial class
    try:
        with SerialCDC(info['port'], info['protocol_baud'], timeout=10, stopbits=2) as serial_connection:
            # The firmware driver wraps a serial port connection which enables a simple command-response transaction
            # This driver structure is defined in pykitcommander.firmwareinterface
            firmware_driver = info['protocol_class'](serial_connection)
            # Make sure communication is synchronized
            firmware_driver.synchronize()

            error_led = info['kit_info']['leds'].ERROR_LED
            connection_led = info['kit_info']['leds'].CONNECTION_LED
            # Switch off error LED in case it was lit due to previous failure
            firmware_driver.firmware_command("MC+SETLED", [error_led,"off"])
            # Turn on connection LED to indicate communication with target
            firmware_driver.firmware_command("MC+SETLED", [connection_led,"on"])
            # Read out firmware version
            version = firmware_driver.firmware_command("MC+VERSION")
            logger.info("Application firmware version: '%s'", version)
            try:
                # Now build the certificates
                logger.info("Building certificates using information from firmware...")
                build_certs_from_ecc(firmware_driver,
                                    signer_cert_filename,
                                    device_cert_filename,
                                    args.device_certificate_template,
                                    args.signer_certificate_template,
                                    args.force)
            except KitCommunicationError as error:
                logger.error(error)
                # Signal error by turning on ERROR LED
                firmware_driver.firmware_command("MC+SETLED", [error_led,"on"])
                # Make sure connection LED is switched off before returning
                firmware_driver.firmware_command("MC+SETLED", [connection_led,"off"])
                return STATUS_FAILURE

            # Send firmware command to turn LED off
            firmware_driver.firmware_command("MC+SETLED", [connection_led,"off"])
            return STATUS_SUCCESS
    except SerialException as exc:
        print("Unable to open port '{}'. Check that the port is not in use, or specify an alternative port."
            .format(info['port']))
        logger.debug(exc, exc_info=True)    # get traceback if debug loglevel
        return STATUS_FAILURE

def _action_create_verification(args):
    """Create verification certificate

    This action will create a verification certificate from a signer CA certificate and private key and write the
    verification certificate to file
    :param args: command line arguments
    :type args: class:`argparse.Namespace`
    :return: Status code (STATUS_SUCCESS or STATUS_FAILURE)
    :rtype: int
    """
    logger = getLogger(__name__)
    output_path = _create_output_folder(args)

    ver_cert_filename = os.path.join(output_path, "verification.crt")

    try:
        build_verification_cert(args.signer_ca_certificate_file,
                                args.signer_ca_key_file,
                                args.registration_code,
                                ver_cert_filename)
    except Exception as error:
        logger.error(error)
        return STATUS_FAILURE

    return STATUS_SUCCESS

def _create_output_folder(args):
    """
    Create output folder if it does not exist

    Output folder is either given by the -o argument or if not specified the current working directory will be used
    :return: output path
    :rtype: str
    """
    # Output path is optional, if not specified use current directory
    output_path = args.output_path
    if output_path is None:
        output_path = '.'

    # Create output folder
    os.makedirs(output_path, exist_ok=True)

    return output_path

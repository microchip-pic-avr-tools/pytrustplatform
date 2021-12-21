"""
Python Trust Platform utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pytrustplatform is a collection of utilities for interacting with Microchip
Trust Platform and Microchip CryptoAuthentication(TM) devices

Fetching data from a certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The cert_get_data module contains functions to fetch various information from
a certificate.

Fetch the Subject Key Identifier from a certificate

.. code-block:: python

    from pytrustplatform.cert_get_data import cert_get_skid
    skid = cert_get_skid("mycertificate.crt")

Fetch Common Name from a certificate:

.. code-block:: python

    from pytrustplatform.cert_get_data import cert_get_common_name
    common_name = cert_get_common_name("mycertificate.crt")

Create Fingerprint from a certificate:

.. code-block:: python

    from pytrustplatform.cert_get_data import create_cert_fingerprint
    fingerprint = create_cert_fingerprint("mycertificate.crt")

Create device certificate and CSR
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The device_cert_builder module contains functions to create device certificates
and Certificate Signing Requests (CSR) for a connected Microchip IoT kit.

.. code-block:: python

    # Ask pykitcommander to setup the kit with the appropriate firmware
    from pykitcommander.kitprotocols import setup_kit
    info = setup_kit('iotprovision')

    # Collect required info to continue:
    port = info['port']
    baud = info['protocol_baud']
    protocol = info['protocol_class']

    # Build the device certificate.  A CSR will be generated as part of the process.
    # Both will be written to file.  The serial port connection uses pyserial, in a
    # context manager to ensure the port is closed after use
    from serial import Serial
    with Serial(port=port, baudrate=baud) as serial_connection:
        firmware_driver = protocol(serial_connection)
        from pytrustplatform.device_cert_builder import build_device_cert
        device_cert = build_device_cert(firmware_driver,
                                        "my_signer-ca.crt",
                                        "my_signer-ca.key",
                                        "generated.csr",
                                        "generated_device.crt")

Create device and signer certificate from ECC data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The ecc_cert_builder module contains functions to create device certificates
and signer certificates from data collected from an ECC device of a connected
Microchip IoT kit.

.. code-block:: python

    # Ask pykitcommander to setup the kit with the appropriate firmware
    from pykitcommander.kitprotocols import setup_kit
    info = setup_kit('iotprovision')

    # Collect required info to continue:
    port = info['port']
    baud = info['protocol_baud']
    protocol = info['protocol_class']

    # Build the device certificate and signer certificate.  Both will be written to file.
    # The serial port connection uses pyserial, in a context manager to ensure the port is
    # closed after use
    from serial import Serial
    with Serial(port=port, baudrate=baud) as serial_connection:
        firmware_driver = protocol(serial_connection)
        from pytrustplatform.ecc_cert_builder import build_certs_from_ecc
        ecc_device_cert, ecc_signer_cert = build_certs_from_ecc(firmware_driver,
                                                                "generated_signer.crt",
                                                                "generated_device.crt")

Create verification certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The verification_cert_builder module contains a function to create verification
certificates.  A verification certificate is typically used when registering a
Certificate Authority (CA) with a cloud provider.

Create a verification certificate from a signer CA certificate and private key

.. code-block:: python

    from pytrustplatform.verification_cert_builder import build_verification_cert
    verification_cert = build_verification_cert("my_signer-ca.crt",
                                                "my_signer-ca.key",
                                                "MY_REGCODE_0123456789",
                                                "generated_verification.crt")

Create chain of trust
~~~~~~~~~~~~~~~~~~~~~
The ca_create module contains functions to create a chain of trust.  Keys can be generated or already
existing keys can be provided

.. code-block:: python

    from pytrustplatform.ca_create import ca_create_root, ca_create_signer_csr, ca_create_signer

    # Create Root, generates root private key (if it does not exist) and root certificate
    ca_create_root("generated_root.key", "generated_root.crt")

    # Create signer CA CSR and signer CA private key (if it does not exist)
    ca_create_signer_csr("generated_signer_ca.key", "generated_signer_ca.csr")

    # Create signer certificate based on previously generated root key, root certificate and signer CSR
    ca_create_signer("generated_signer_ca.csr",
                     "generated_signer_ca.crt",
                     "generated_root.key",
                     "generated_root.crt")

Logging
~~~~~~~
This package uses the Python logging module for publishing log messages to
library users.  A basic configuration can be used (see example below), but for
best results a more thorough configuration is recommended in order to control
the verbosity of output from dependencies in the stack which also use logging.
See logging.yaml which is included in the package (although only used for CLI)

Simple logging configuration example:

.. code-block:: python

    import logging
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.WARNING)

Dependencies
~~~~~~~~~~~~
pytrustplatform depends on pykitcommander to manage Microchip IoT kit firmware
and connection.
pytrustplatform depends on pyedbglib for its transport protocol.
pyedbglib requires a USB transport library like libusb.
See pyedbglib package for more information.
"""

import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

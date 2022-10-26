# pytrustplatform
pytrustplatform is a collection of utilities for interacting with Microchip Trust Platform and
Microchip CryptoAuthentication™ devices

![PyPI - Format](https://img.shields.io/pypi/format/pytrustplatform)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pytrustplatform)
![PyPI - License](https://img.shields.io/pypi/l/pytrustplatform)

## Overview
pytrustplatform is available:

* install using pip from pypi: https://pypi.org/project/pytrustplatform
* browse source code on github: https://github.com/microchip-pic-avr-tools/pytrustplatform
* read API documentation on github: https://microchip-pic-avr-tools.github.io/pytrustplatform
* read the changelog on github: https://github.com/microchip-pic-avr-tools/pytrustplatform/blob/main/CHANGELOG.md

## Usage
pytrustplatform can be used as a command-line interface or a library

## Command-line interface
pytrustplatform is a multi-layered command-line interface meaning that there are several commands each
with its own actions and options.

Getting help:
```bash
pytrust --help
```
Getting help for specific command:
```bash
pytrust certificate --help
```
The amount of logging is controlled by the -v/--verbose option:
```bash
pytrust -v info
```
Possible log levels are `debug`, `info`, `warning`, `error`, `critical`.  Default is `info`.

Print version info and exit:
```bash
pytrust -V
```
Print release info and exit:
```bash
pytrust -R
```
### General about command line options
Many command line options can be specified with a short form preceded with a single dash (like `-o`) or an equivalent long form preceded with double dashes (like `--output-path`). Some options only have the long form. Regardless, long options can be abbreviated to a prefix, if the abbreviation is unambiguous (the prefix matches a unique option). Example: `--organization-name` can be abbreviated to `--org` but not to `--o`. An error is produced for arguments that would match more than one option.

### Commands reading information from connected Microchip IoT kit
Some commands need to read information from the ECC chip on a Microchip IoT kit, which must be connected to a USB port.
In case, pytrustcommander will normally connect to the kit automatically, and program the required firmware into it.
If there is more than one suitable IoT kit connected, the user must select which one to use using the
-s/--serialnumber option. If the -s option is not used in this situation, a list of kits is printed.
It is sufficient to specify enough digits from the end of the serial number to make it unique.
Sample session with two kits connected:
```bash
pytrust cert read-ecc-serialnumber
ERROR - Multiple kits found.
ERROR - Please specify serial number ending digits for the one you want
ERROR - Tool: nEDBG CMSIS-DAP Serial: MCHP3203081800007239 Device: ATmega4808
ERROR - Tool: nEDBG CMSIS-DAP Serial: MCHP3261021800001323 Device: PIC24FJ128GA705

pytrust -s9 cert read-ecc-serialnumber
Reading ECC serial number from kit
012370A530B9A4A8FE

```

### Certificate command
The certificate command support certificate manipulation and parsing actions.  It can also be invoked using the cert alias:
```bash
pytrust certificate
```
is the same as
```bash
pytrust cert
```

#### Action: get-skid
Get the Subject Key Identifier from a certificate. The SKID is printed to standard output.
* use --cert to specify certificate file

Example:
```bash
pytrust certificate get-skid --cert mycertificate.crt
```

#### Action: get-common-name
Get the Common Name from a certificate. The Common Name is printed to standard output.
* use --cert to specify certificate file

Example:
```bash
pytrust certificate get-common-name --cert mycertificate.crt
```

#### Action: create-from-ecc
Create device and signer certificates using compressed certificate data read out from the ECC device.
This comamnd requires a Microchip IoT kit is connected. The device and signer certificate are stored in
output folder in files named "device_ecc608.crt" and "signer_ecc608.crt", respectively.
* use -dct to optionally specify a device certificate template file
* use -sct to optionally specify a signer certificate template file
* use -o to optionally specify a path to store the certificates created (defaults to '.')

Example:
```bash
pytrust certificate create-from-ecc -o mycertificates
```

#### Action: create-csr
Create a device Certificate Signing Request (CSR) from data read out from the ECC device.
This comamnd requires a Microchip IoT kit is connected. The CSR will be written to a file in output folder, in file "device.csr".

Example:
```bash
pytrust certificate create-csr
```

#### Action: create-from-csr
Create a device certificate using a Certificate Signing Request (CSR) created from data read out from the ECC device. This comamnd requires a Microchip IoT kit is connected. Both the certificate and the CSR will be written to files in output folder, in files "device.crt" and "device.csr", respectively.
* use -scak to specify signer Certificate Authority (CA) private key file
* use -scac to to specify signer Certificate Authority (CA) certificate file
* use -o to optionally specify a path to store the certificate and CSR created (defaults to '.')

Example:
```bash
pytrust certificate create-from-csr -o mycertificates -scak my_signer-ca.key -scac my_signer-ca.crt
```

#### Action: create-verification
Create a verification certificate from a signer Certificate Authority (CA) certificate and private key.
Certificate is placed in output folder, file name "verification.crt".
The verification certificate is typically used when registering the CA with a cloud provider.
* use -scak to specify signer Certificate Authority (CA) private key file
* use -scac to to specify signer Certificate Authority (CA) certificate file
* use --registration-code to specify the registration code to be used in the verification certificate
* use -o to optionally specify a path to store the certificate created (defaults to '.')

Example:
```bash
pytrust certificate create-verification -o mycertificates -scac my_signer_ca.crt -scak my_signer_ca.key --reg 0123456789
```
#### Action: fingerprint
Generates a fingerprint from a certificate file passed in. The fingerprint is printed to standard output.

Example:
```bash
pytrust cert fingerprint -cert device.crt
```

#### Action: create-chain-of-trust
Create a chain of trust with root CA, signer CSR and signer certificates at current or specified folder.
The certificates are placed in the output folder, filenames "root-ca.crt", "signer-ca.csr", and "signer-ca.crt",
respectively.
* use -o to optionally specify a path to store the certificate created (defaults to '.')
* use --org to optionally change issuer Organization name (defaults to 'Example Inc')
* use --root-common-name to optionally change root CA certificate Common Name (defaults to 'Example Root CA')
* use -signer-common-name to optionally change signer CA certificate Common Name (defaults to 'Example Signer FFFF')


Example:
```bash
pytrust cert -o my-root-certs --org "Microchip Technology Inc" -rcn "Microchip Root CA" -scn "Microchip Signer" create-chain-of-trust
```

### Manifest command
The manifest command supports building of, decoding and searching in Microchip secure elements manifests.
```bash
pytrust manifest
```
is the same as
```bash
pytrust man
```

#### Action: create-from-certificates
Creates a manifest based on a device and signer certificate.
```bash
pytrust manifest create-from-certificates manifest-file.json --manifest-signer-cert my_manifest_signer.crt --manifest-signer-key my_manifest_signer.key --device-cert device.crt --signer-cert signer.crt
```

#### Action: create-from-secure-element
Create a manifest based on a secure element. This command will only work with supported development kits e.g. AVR-IoT/PIC-IoT. The tool will automatically detect any connected supported development tool, load the provisioning bridge FW and get all data required to build the secure element in the manifest from the secure element.
```bash
pytrust manifest create-from-secure-element manifest.json --manifest-signer-cert manifest_signer.crt --manifest-signer-key manifest_signer.key
```

#### Action: get-certificates
Extracts certificates from secure elements in the manifest.
With no parameters it will extract all secure element "device certificates" and put them into the current directory.
```bash
pytrust manifest get-certificates manifest-file.json
```

Below example extracts both certificates (0=device certificate, 1=signer certificate) for all secure elements in the manifest and puts them into the `./my_output_dir` directory.
```bash
pytrust manifest get-certificates manifest-file.json --cert-index 0,1 --outdir ./my_output_dir
```

Extract device and signer certificates only for the secure element with `--id 01230390b3d1450c01` and put them into ./my_output_dir directory.
```bash
pytrust manifest get-certificates manifest-file.json --cert-index 0,1 --outdir ./my_output_dir --id 01230390b3d1450c01
```

#### Action: get-secure-element
Get a secure element from the manifest by providing a unique ID.
 ```bash
pytrust manifest get-secure-element manifest-file.json --id 01230390b3d1450c01
```

#### Action: list-secure-element-ids
List all secure element IDs that are present in the manifest.
```bash
pytrust manifest list-secure-element-ids manifest-file.json
```

#### Action: list-secure-elements
List secure elements that are present in the manifest. The full content of each manifest will be printed.
```bash
pytrust manifest list-secure-elements manifest-file.json
```

## Library
pytrustplatform is a collection of utilities and it can be used as a library by accessing the individual modules.

### Logging
This package uses the Python logging module for publishing log messages to library users.
A basic configuration can be used (see example below), but for best results a more thorough configuration is
recommended in order to control the verbosity of output from dependencies in the stack which also use logging.
See logging.yaml which is included in the package (although only used for CLI).
```python
# pytrustplatform uses the Python logging module
import logging
logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.WARNING)
```

### Fetching data from a certificate
The `cert_get_data` module contains functions to fetch various information from a certificate. For example:
```python
# Fetch the Subject Key Identifier from a certificate
from pytrustplatform.cert_get_data import cert_get_skid
skid = cert_get_skid("mycertificate.crt")

# Fetch Common Name from a certificate:
from pytrustplatform.cert_get_data import cert_get_common_name
common_name = cert_get_common_name("mycertificate.crt")
```

### Create device certificate from CSR
Building a device certificate will implicitly generate a Certificate Signing Request (CSR)
```python
from serial import Serial
from pytrustplatform.device_cert_builder import build_device_cert
from pykitcommander.kitprotocols import setup_kit

# Fetch a protocol object from pykitcommander
info = setup_kit('iotprovision')

# Collect required info to continue:
port = info['port']
baud = info['protocol_baud']
protocol = info['protocol_class']

# Use the Serial driver with context manager to be sure port is closed after use
with Serial(port=port, baudrate=baud) as serial_connection:
    firmware_driver = protocol(serial_connection)
    # Build device certificate.  A CSR will be generated as part of the process.  Both will be written to file
    build_device_cert(firmware_driver, "my_signer-ca.crt", "my_signer-ca.key", "generated.csr", "generated_device.crt")
```

### Create verification certificate
```python
from pytrustplatform.verification_cert_builder import build_verification_cert

build_verification_cert("my_signer-ca.crt", "my_signer-ca.key", "MY_REGCODE_0123456789", "generated_verification.crt")
```

### Create device and signer certificate from ECC data
Generate certificates from compressed certificates on an ECC device

```python
from serial import Serial
from pykitcommander.kitprotocols import setup_kit
from pytrustplatform.ecc_cert_builder import build_certs_from_ecc

# Fetch a protocol object from pykitcommander
info = setup_kit('iotprovision')

# Collect required info to continue:
port = info['port']
baud = info['protocol_baud']
protocol = info['protocol_class']

# Use the Serial driver with context manager to be sure port is closed after use
with Serial(port=port, baudrate=baud) as serial_connection:
    firmware_driver = protocol(serial_connection)
    # Build device certificate and signer certificate.  Both will be written to file.
    ecc_device_cert, ecc_signer_cert = build_certs_from_ecc(firmware_driver, "generated_signer.crt", "generated_device.crt")
```

### Create chain of trust
Create a chain of trust.  Keys can be generated or already existing keys can be provided

```python
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
```
## Linux systems
This package uses pyedbglib and other libraries for USB transport and some udev rules are required.
For details see the pyedbglib package: https://pypi.org/project/pyedbglib

"""Microchip Secure Element Manifest library.

Main library features:
* building of manifests
* verifying signed secured elements
* searching in manifests
* extracting secured elements from manifest
"""
import json
import pprint
import pathlib
from logging import getLogger
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import hexlify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.utils import int_to_bytes
import jose.jws
# pylint: disable=invalid-name
VERIFICATION_CERTIFICATES_FOLDER = pathlib.Path(
    __file__).parent.absolute() / "mchp_manifest_signers"


def urlsafe_b64decode_unpadded(s):
    """Unpadded url-safe base64 decoding

    :param s: Base64 encoded data without padding (no "=" padding)
    :type s: str, bytes
    :return: Decoded data
    :rtype: bytes
    """
    return urlsafe_b64decode(s + "==")


def urlsafe_b64encode_unpadded(s):
    """Unpadded url-safe base64 encoding.

    :param s: Data to encode.
    :type s: bytes
    :return: Base64 encoded data without padding (no "=" padding)
    :rtype: bytes
    """
    return urlsafe_b64encode(s).decode('ascii').rstrip('=')


def load_cert(cert_file_name, encoding="pem"):
    """Load certificate from file.

    :param cert_file_name: File name
    :type cert_file_name: str
    :param encoding: Certificate encoding, either pem or der, defaults to "pem"
    :type encoding: str, optional
    :return: Certificate object as defined in cryptography library.
    :rtype: Certificate object
    """
    if encoding == "pem":
        with open(cert_file_name, "rb") as file:
            cert = x509.load_pem_x509_certificate(
                data=file.read(), backend=default_backend())
    else:
        with open(cert_file_name, "rb") as file:
            cert = x509.load_der_x509_certificate(
                data=file.read(), backend=default_backend())
    return cert


class SecureElement:
    """Secure Element.
    """

    def __init__(self):
        self.version = 1
        self.model = ''
        self.partNumber = ''
        self.manufacturer = {
            'organizationName': '',
            'organizationalUnitName': ''}
        self.provisioner = {
            'organizationName': '',
            'organizationalUnitName': ''}
        self.distributor = {
            'organizationName': '',
            'organizationalUnitName': ''}
        self.provisioningTimestamp = ''
        self.uniqueId = ''
        self.publicKeySet = dict()

    def __repr__(self):
        return pprint.pformat(self.__dict__)

    def get_certificate(self, key_index, cert_index):
        """Get certificate from secure element

        :param cert_index: Certificate index. If the public key has a certificate associated with it,
                    then that certificate will be found at the first index position. Subsequent certificates
                    in the array will be the CA certificates used to validate the previous one.
        :type cert_index: int
        :param key_index: Key the certificate(s) are associated with.
        :type key_index: int
        :return: Certificate in BASE64 encoded (not unpdadded BASE64URL, and not PEM) strings of the DER
                 certificate. This is defined in RFC7517 section 4.7.
        :rtype: str
        """
        return self.publicKeySet['keys'][key_index]['x5c'][cert_index]

    def set_provisioning_time(self, time):
        """Set the secure element provisioning timestamp.

        :param time: Date and time the secured element was provisioned in UTC.
                     This is usually taken from the device certificate "not valid before" field.
        :type time: datetime
        """
        self.provisioningTimestamp = time.strftime(
            '%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    def set_unique_id(self, uniqueid):
        """Set the unique identifier for the secure element.

        :param uniqueid: Unique identifier for the secure element. For Crypto Authentication devices, this is the 9
                        byte device serial number or a lower-case hex string.
        :type uniqueid: str, bytes
        """
        if isinstance(uniqueid, str):
            self.uniqueId = uniqueid
        elif isinstance(uniqueid, bytearray):
            self.uniqueId = uniqueid.hex()

    def set_publicJWK(self, kid, kty='', crv='', x=None, y=None, x5c=None):
        """Add a public JSON Web Key (JWK) element to the secure element.

        :param kid: Key ID string. This uniquely identifies this key on the secure element.
                    For Crypto Authentication secure elements, this will be the slot number
                    of the corresponding private key.
        :type kid: str
        :param kty: Key type. Crypto Authentication secure elements only support "EC" public keys as defined in
                    RFC 7518 section 6.1., defaults to ''.
        :type kty: str, optional
        :param crv: For elliptic curve keys, this is the curve name. Crypto Authentication secure elements
                    only support the "P-256" curve as defined in RFC 7518 section 6.2.1.1., defaults to ''
        :type crv: str, optional
        :param x: Unpadded BASE64URL encoded x component of the public key. For elliptic curve keys, this is
                  the encoded public key X integer as defined in RFC 7518 section 6.2.1.2., defaults to None
        :type x: str, optional
        :param y: Unpadded BASE64URL encoded x component of the public key. For elliptic curve keys, this is the
                encoded public key Y integer as defined in RFC 7518 section 6.2.1.3., defaults to None
        :type y: str, optional
        :param x5c: If the public key has a certificate associated with it, then that certificate will be
                    found at the first position in this array. Subsequent certificates in the array will be
                    the CA certificates used to validate the previous one. Certificates will be BASE64 encoded
                    (not unpdadded BASE64URL) strings of the DER certificate. This is defined in
                    RFC7517 section 4.7., defaults to None
        :type x5c: str, optional
        """
        publicJWK = dict()
        publicJWK['kid'] = kid
        if kty in ['EC', 'RSA', 'oct']:
            publicJWK['kty'] = kty
        if crv in ['P-256', 'P-384', 'P-521']:
            publicJWK['crv'] = crv
        if x is not None:
            publicJWK['x'] = x
        if y is not None:
            publicJWK['y'] = y
        if isinstance(x5c, list):
            publicJWK['x5c'] = x5c

        if 'keys' not in self.publicKeySet:
            self.publicKeySet['keys'] = []

        self.publicKeySet['keys'].append(publicJWK)


class TnGoTlsSecureElement(SecureElement):
    """Trust and Go Secure Element.
    """

    def __init__(self):
        super().__init__()
        self.model = 'ATECC608B'
        self.partNumber = 'ATECC608B-TNGTLS'
        self.manufacturer = {
            'organizationName': 'Microchip Technology Inc',
            'organizationalUnitName': 'Secure Products Group'}
        self.provisioner = {
            'organizationName': 'Microchip Technology Inc',
            'organizationalUnitName': 'Secure Products Group'}
        self.distributor = {
            'organizationName': 'Microchip Technology Inc',
            'organizationalUnitName': 'Microchip Direct'}

    def build(self, data_provider):
        """Build the secure element.

        :param data_provider: Data provider that implements ManifestDataProvider abstract class.
        :type data_provider: ManifestDataProvider implementation
        """
        ser_num = data_provider.get_serial_number()
        self.set_unique_id(ser_num)
        self.set_provisioning_time(data_provider.get_provisioning_time())
        for ec_priv_key in [0, 1, 2, 3, 4]:
            public_key = bytearray()
            public_key = data_provider.get_pubkey(ec_priv_key)
            if public_key:
                x = urlsafe_b64encode_unpadded(public_key[0:32])
                y = urlsafe_b64encode_unpadded(public_key[32:64])
                if ec_priv_key == 0:
                    cert_chain = list()
                    cert_chain.append(data_provider.get_certificate(0))
                    cert_chain.append(data_provider.get_certificate(1))
                    self.set_publicJWK(str(ec_priv_key), 'EC',
                                    'P-256', x, y, x5c=cert_chain)
                else:
                    self.set_publicJWK(str(ec_priv_key), 'EC',
                                    'P-256', x, y, x5c=None)

    def get_device_certificate(self):
        """Get the device certificate

        :return: Device certificate in BASE64 format.
        :rtype: str
        """
        return self.publicKeySet['keys'][0]['x5c'][0]

    def get_signer_certificate(self):
        """Get the signer certificate

        :return: Signer certificate in BASE64 format.
        :rtype: str
        """
        return self.publicKeySet['keys'][0]['x5c'][1]

class TnFlexTlsSecureElement(TnGoTlsSecureElement):
    """Trust and Go Secure Element.
    """
    def __init__(self):
        super().__init__()
        self.partNumber = 'ATECC608B-TFLXTLS'

class TcustomTlsSecureElement(TnGoTlsSecureElement):
    """Trust and Go Secure Element.
    """
    def __init__(self):
        super().__init__()
        self.partNumber = 'ATECC608B-TCSM'

SECURE_ELEMENTS_MAP = {"ATECC608B-TNGTLS": TnGoTlsSecureElement,
                       "ATECC608B-TFLXTLS": TnFlexTlsSecureElement,
                       "ATECC608B-TCSM": TcustomTlsSecureElement}

class SignedSecureElement:
    """Manifest Signed Secure Element
    """
    def __init__(self, secure_element, signer_ca=None):
        """Class initialization

        :param secure_element: Signed Secure Element as dictionary for decoding/verifying or a
                               SecureElement instance to build a signed secure element.
        :type secure_element: SecureElement or any subclass e.g. TnGoSecureElement, or dict containing
                              a signed secured element
        :param signer_ca: Manifest signer to verify or sign the signed secured element, defaults to None.
                          Mandatory when building a signed secure element. Optional for loading/decoding, but
                          when provided the data will be verified with the public key of the certificate.
        :type signer_ca: ManifestSigner, optional
        :raises ValueError: Raised when a signed secured element should be built but no manifest signer was provided.
        """
        self.logger = getLogger(__name__)
        if signer_ca:
            self.signer_ca = signer_ca

        if isinstance(secure_element, SecureElement):
            # If secure element is provided the intention is to build a signed secured element and
            # for that need the manifest signer.
            if not self.signer_ca:
                raise ValueError(
                    "Need a CA cert and private key to sign secure element")
            self.encode(secure_element)
        else:
            self.signed_secure_element = secure_element

    def __repr__(self):
        """Pretty print the signed secure element

        :return: Signed secure element as pretty text.
        :rtype: str
        """
        return pprint.pformat(self.signed_secure_element)

    def verify(self):
        """Verify the signed secured element.

        The function will check if the certificate provided through the class initialization matches the
        fingerprint of the signed secure element signer. If not, it will check the Microchip manifest signers
        that are included in this library for a matching fingerprint. If a matching certificate is found
        its public key is used to verify the signed secured element. If no match is found a ValueError is
        raised.
        """
        protected = json.loads(urlsafe_b64decode_unpadded(
            self.signed_secure_element['protected']))
        fingerprint = urlsafe_b64decode_unpadded(protected['x5t#S256'])

        # Try to find the correct signer certificate based on fingerprint
        if self.signer_ca.fingerprint != fingerprint:
            cert = self.signer_ca.find_cert(fingerprint)
            if cert is None:
                raise ValueError(f"No verification certificate found with SHA256 fingerprint that matches \
                    the fingerprint {hexlify(fingerprint)} in the Signed Secure Element Protected Header")

        verification_algorithms = ['RS256', 'RS384',
                                   'RS512', 'ES256', 'ES384', 'ES512']

        jws_compact = '.'.join([
            self.signed_secure_element['protected'],
            self.signed_secure_element['payload'],
            self.signed_secure_element['signature']
        ])
        # Verify and decode the payload
        jose.jws.verify(
            token=jws_compact,
            key=self.signer_ca.public_key,
            algorithms=verification_algorithms
        )
        self.logger.info("Verified signature of secure element %s", self.signed_secure_element['header']['uniqueId'])

    def get_secure_element(self, se_type=None):
        """Get secure element.

        :param se_type: Secure element type e.g. TnGoTlsSecureElement, defaults to None.
                        If no type is provided the partNumber field in the signed
                        secured element is checked to find a match. If this is unsucessful
                        a generic SecureElement will be returned.
        :type se_type: SecureElement or any sub-class e.g. TnGoSecureElement, optional
        :return: Secure element.
        :rtype: SecureElement or subclass thereof
        """
        se_properties = json.loads(urlsafe_b64decode_unpadded(
            self.signed_secure_element['payload']))
        # Lets try to guess what secure element type this is
        if se_type is None:
            se_type = SECURE_ELEMENTS_MAP.get(se_properties['partNumber'])
            if se_type is None:
                se_type = SecureElement
        assert issubclass(se_type, SecureElement)

        secure_element = se_type()
        secure_element.__dict__ = se_properties
        return secure_element

    def encode(self, secure_element):
        """Build the signed secured element.

        :param secure_element: Secure element to build the signed secured element.
        :type secure_element: SecureElement or instance thereof.
        :return: Signed secured element
        :rtype: str
        """
        assert isinstance(secure_element, SecureElement)
        protected_header = {
            'typ': 'JWT',
            'alg': 'ES256',
            'kid': urlsafe_b64encode_unpadded(
                self.signer_ca.cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value.digest),
            'x5t#S256': urlsafe_b64encode_unpadded(self.signer_ca.fingerprint)
        }
        signed_secure_element = {
            'payload': urlsafe_b64encode_unpadded(json.dumps(secure_element.__dict__).encode('ascii')),
            'protected': urlsafe_b64encode_unpadded(json.dumps(protected_header).encode('ascii')),
            'header': {
                'uniqueId': secure_element.uniqueId
            }
        }

        tbs = signed_secure_element['protected'] + \
            '.' + signed_secure_element['payload']
        signature = self.signer_ca.private_key.sign(
            tbs.encode('ascii'), ec.ECDSA(hashes.SHA256()))
        r_int, s_int = utils.decode_dss_signature(signature)
        signed_secure_element['signature'] = urlsafe_b64encode_unpadded(
            int_to_bytes(r_int, 32) + int_to_bytes(s_int, 32))

        self.signed_secure_element = signed_secure_element
        return signed_secure_element


class ManifestSigner:
    """Manifest signer

    The manifest signer is used to verify manifest entries and to sign
    new entries.
    """
    fingerprint = bytes()

    def __init__(self, cert=None, key=None):
        """Class initialization

        :param cert: Manifest signer certificate file. Certificate must be in PEM format.
        :type cert: str.
        :param key: Manifest signer private key file. Key must be in PEM format.
        :type key: str.
        """
        self.logger = getLogger(__name__)
        if cert:
            self.load(cert, key=key)

    def load(self, certificate, key=None):
        """Initialize the manifest signer with new certificate and key

        :param certificate: Manifest signer certificate
        :type certificate: Certificate
        :param key: Manifest signer key, defaults to None. Not needed when only reading manifests.
        :type key: bytes or bytearray, optional
        """
        if not isinstance(certificate, x509.Certificate):
            self.cert = x509.load_pem_x509_certificate(
                certificate, backend=default_backend())
        else:
            self.cert = certificate
        self.fingerprint = self.cert.fingerprint(hashes.SHA256())
        self.public_key = self.cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if key:
            self.private_key = serialization.load_pem_private_key(
                key, password=None, backend=default_backend())

    def find_cert(self, fingerprint, path=VERIFICATION_CERTIFICATES_FOLDER):
        """Find a certificate that matches a fingerprint and load it.

        The certificates in the path location must be in PEM format.

        :param fingerprint: Certificate fingerprint (SHA256 of a certificate in DER format)
        :type fingerprint: bytes, bytearray
        :param path: Path to check for certificates, defaults to VERIFICATION_CERTIFICATES_FOLDER
        :type path: str, optional
        :return: Certificate
        :rtype: Certificate
        """
        for file in pathlib.Path(path).iterdir():
            cert = load_cert(file)
            if fingerprint == cert.fingerprint(hashes.SHA256()):
                self.logger.info("Matching verification certificate found in: %s", file)
                self.load(cert)
                return cert
        return None


class Manifest:
    """Manifest

    Container for Microchip manifests.
    """
    def __init__(self, manifest=None, signer_ca=None):
        """Manifest class initialization

        :param manifest: Manifest, defaults to None
        :type manifest: list, str, bytes, bytearray, optional
        :param signer_ca: Manifest signer to sign new entries or to verfify existing entries, defaults to None
        :type signer_ca: ManifestSigner, optional
        """
        self.manifest = []
        self.index = 0
        self.signer_ca = signer_ca

        if manifest:
            if type(manifest) in [str, bytes, bytearray]:
                manifest = json.loads(manifest)
            self.manifest = manifest
            self.manifest_entries = len(manifest)

    def __iter__(self):
        """Manifest iterator.

        :return: Current instance of the Manifest
        :rtype: Manifest
        """
        return self

    def __next__(self):
        """Next element of the iteration.

        :raises StopIteration: When end of iteration is reached.
        :return: Next signed secured element in the manifest.
        :rtype: SignedSecureElement
        """
        if self.index >= self.manifest_entries:
            raise StopIteration
        signed_secure_element = SignedSecureElement(
            self.manifest[self.index], signer_ca=self.signer_ca)
        self.index += 1
        return signed_secure_element

    def find_secure_element(self, identifier):
        """Find secure element in Manifest.

        :param identifier: Secure element Identifier e.g. for ECC devices the hex encoded
                           serial number in lower case letters.
        :type identifier: str
        :return: Signed secure element if sucessfull otherwise None.
        :rtype: SignedSecureElement or None
        """
        for signed_secure_element in self.manifest:
            if signed_secure_element['header']['uniqueId'].lower() == identifier.lower():
                return SignedSecureElement(signed_secure_element)
        return None

    def append(self, secure_element):
        """Add a new entry in the Manifest

        :param secure_element: Secure element or signed secure element.
        :type secure_element: SignedSecureElement, SecureElement
        """
        if isinstance(secure_element, SecureElement):
            sse = SignedSecureElement(secure_element, signer_ca=self.signer_ca)
        elif isinstance(secure_element, SignedSecureElement):
            sse = secure_element
        else:
            raise TypeError(f"Expected SignedSecureElement or SecureElement but got {type(secure_element)}")
        self.manifest.append(sse.signed_secure_element)
        self.manifest_entries = len(self.manifest)

    def dumps(self):
        """Serialize the Manifest

        :return: Manifest as pretty formatted json.
        :rtype: str
        """
        return json.dumps(self.manifest, indent=2)

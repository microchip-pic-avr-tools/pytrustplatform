"""
pytrustplatform manifest functions
"""
from pathlib import Path
from base64 import b64decode
from logging import getLogger
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from .manifest import Manifest, ManifestSigner, TnGoTlsSecureElement
from .data_provider import CertsData, EccDataProvider
from .manifest import SECURE_ELEMENTS_MAP

# pylint: disable=invalid-name
def list_secure_elements(manifest):
    """List secure elements from manifest

    :param manifest: Manifest to parse for secure elements. Json encoded data (str, bytes, bytearray) or
                     already decoded data (str).
    :type manifest: list, str, bytes, bytearray
    :returns: list of elements
    :rtype: list of str
    """
    man = Manifest(manifest)
    elements = []
    for sse in man:
        se = sse.get_secure_element()
        elements.append(se)
    return elements

def extract_certificates(manifest, unique_id: None = None, key_index: int = 0, cert_indexes=None,
                         file_names="common-name", outdir=None):
    """Extracts certificates from secure elements in a manifest

    :param manifest: Manifest
    :type manifest: str, list, bytes, bytearray
    :param unique_id: If provided the certificates will only be extracted for the secure element with
                      the same unique ID, defaults to None
    :type unique_id: str, optional
    :param key_index: Certificates correspond to a key in the secure element and this index defines
                      for which key the certificates should be extracted, defaults to 0
    :type key_index: int, optional
    :param cert_indexes: Defines which certificates in the chain should be extracted. Index 0 is the
                         first certificate in the chain (device certificate), subsequent certificates
                         will be the "CA" certificates used to verify the previous one (e.g. index 1
                         is the signer certificate that can verify the device certificate at index 0.
                         If several certificates should be extracted add their index to the list e.g. [0,1],
                         defaults to [0]
    :type cert_indexes: list, optional
    :param file_names: File name of the extracted certificates, either "common-name" which uses the
                       certificate subject common name as file name, or "fingerprint" which uses the
                       fingerprint of the certificate as file name (SHA256 of cert in DER format),
                       defaults to "common-name"
    :type file_names: str, optional
    :param outdir: Output folder where extracted certificates should be stored, defaults to None which will
                   put the certificate in the folder from which the script was executed.
    :type outdir: str, optional
    """
    certificates = []
    # Default value list:
    if not cert_indexes:
        cert_indexes=[0]
    man = Manifest(manifest)
    if unique_id:
        se = man.find_secure_element(unique_id)
        certificates.extend(extract_certificates_from_secure_element(se, key_index, cert_indexes, file_names, outdir=outdir))
    else:
        for sse in man:
            se = sse.get_secure_element()
            certificates.extend(extract_certificates_from_secure_element(se, key_index, cert_indexes, file_names, outdir=outdir))
    return certificates


def extract_certificates_from_secure_element(secure_element, key_index=0, cert_indexes=None,
                                             file_names="common-name", outdir=None):
    """Extract certificates from a secure element

    Fetches certificates from a secure element and saves them in a directory.

    :param secure_element: Secure element
    :type secure_element: SecureElement or any subclass thereof
    :param key_index: Certificates correspond to a key in the secure element and this index defines
                      for which key the certificates should be extracted, defaults to 0
    :type key_index: int, optional
    :param cert_indexes: Defines which certificates in the chain should be extracted. Index 0 is the
                         first certificate in the chain (device certificate), subsequent certificates
                         will be the "CA" certificates used to verify the previous one (e.g. index 1
                         is the signer certificate that can verify the device certificate at index 0.
                         If several certificates should be extracted add their index to the list e.g. [0,1],
                         defaults to [0]
    :type cert_indexes: list, optional
    :param file_names: File name of the extracted certificates, either "common-name" which uses the
                       certificate subject common name as file name, or "fingerprint" which uses the
                       fingerprint of the certificate as file name (SHA256 of cert in DER format),
                       defaults to "common-name"
    :type file_names: str, optional
    :param outdir: Output folder where extracted certificates should be stored, defaults to None which will
                   put the certificate in the folder from which the script was executed.
    :type outdir: str, optional
    """
    files_created = []
    # Default value list:
    if not cert_indexes:
        cert_indexes=[0]
    for index in cert_indexes:
        b64_data = secure_element.get_certificate(key_index, index)
        if b64_data:
            der_data = b64decode(b64_data)
            cert = x509.load_der_x509_certificate(data=der_data, backend=default_backend())
            if file_names == "fingerprint":
                file_name = cert.fingerprint(hashes.SHA256())
            elif file_names == "common-name":
                file_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            else:
                raise ValueError(f"{file_names} is not a valid file name option")
            file_name = file_name + ".cer"
            if outdir:
                file_name = str(Path(outdir, file_name))
            with open(file_name, "wb") as cert_file:
                cert_file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
                files_created.append(file_name)
    return files_created

def get_secure_element(manifest, secure_element_id):
    """Get a secure element from manifest by its unique ID

    :param manifest: Manifest file.
    :type manifest: str
    :param id: Unique ID of the secure element (e.g. serial number of ATECC608)
    :type id: str
    """
    logger = getLogger(__name__)
    man = Manifest(manifest)
    secure_element = man.find_secure_element(secure_element_id)
    if not secure_element:
        logger.error("Secure element with unique ID '%s' not found in manifest", secure_element_id)
        return None
    se = secure_element.get_secure_element()
    return se

def list_secure_element_ids(manifest):
    """List secure elements unique ID from manifest

    :param manifest: Manifest file
    :type manifest: str
    :returns: list of elements
    :rtype: list of str
    """
    elements = []
    man = Manifest(manifest)
    for sse in man:
        id = sse.signed_secure_element['header']['uniqueId']
        elements.append(id)
    return elements

def create_manifest_from_certs(manifest, manifest_signer_cert, manifest_signer_key,
                               device_cert, signer_cert, ecc_type=None):
    """Create a manifest based on device and signer certificates

    :param manifest: Manifest file name
    :type manifest: str
    :param manifest_signer_cert: Manifest signer certificate path
    :type manifest_signer_cert: str
    :param manifest_signer_key: Manifest signer private key path
    :type manifest_signer_key: str
    :param device_cert: Device certificate path
    :type device_cert: str
    :param signer_cert: Signer certificate path
    :type signer_cert: str
    :param ecc_type: Type of secure element. Last part of the order code e.g. TNGOTLS or TFLXTLS
    :type ecc_type: str
    """
    logger = getLogger(__name__)
    with open(manifest_signer_cert, "rb") as cert_file:
        with open(manifest_signer_key, "rb") as key_file:
            manifest_signer = ManifestSigner(cert_file.read(), key=key_file.read())
    man = Manifest(signer_ca=manifest_signer)
    data_provider = CertsData(device_cert, signer_cert)
    se = None
    if ecc_type:
        for key, se_type in SECURE_ELEMENTS_MAP.items():
            if key.find(ecc_type) > -1:
                se = se_type()
    if not se:
        logger.info("No secure element type provided. Using Trust & Go.")
        se = TnGoTlsSecureElement()
    se.build(data_provider)
    man.append(se)
    with open(manifest, "w", encoding="utf-8") as manifest_file:
        manifest_file.write(man.dumps())
    return manifest

def create_manifest_from_secure_element(manifest, manifest_signer_cert, manifest_signer_key):
    """Create a manifest from a secure element.

    :param manifest: Manifest file name
    :type manifest: str
    :param manifest_signer_cert: Manifest signer certificate path
    :type manifest_signer_cert: str
    :param manifest_signer_key: Manifest signer private key path
    :type manifest_signer_key: str
    """
    with open(manifest_signer_cert, "rb") as cert_file:
        with open(manifest_signer_key, "rb") as key_file:
            manifest_signer = ManifestSigner(cert_file.read(), key=key_file.read())
    man = Manifest(signer_ca=manifest_signer)
    data_provider = EccDataProvider()
    se = data_provider.get_secure_element()
    man.append(se)
    with open(manifest, "w", encoding="utf-8") as manifest_file:
        manifest_file.write(man.dumps())
    return manifest

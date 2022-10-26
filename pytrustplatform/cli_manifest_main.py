"""
Manifest CLI utility entry point
"""
from .manifest.manifest_functions import create_manifest_from_certs, create_manifest_from_secure_element, get_secure_element
from .manifest.manifest_functions import list_secure_element_ids, list_secure_elements, extract_certificates
from .status_codes import STATUS_SUCCESS, STATUS_FAILURE

def manifest_cli_handler(args):
    """
    Entry point for manifest command of CLI
    """
    if args.action in ["get-secure-element", "list-secure-elements", "list-secure-element-ids", "get-certificates"]:
        with open(args.manifest, "r") as manifest_file:
            manifest = manifest_file.read()
    if args.action == "create-from-certificates":
        manifest_file = create_manifest_from_certs(args.manifest, args.manifest_signer_cert, args.manifest_signer_key,
                                              args.device_cert, args.signer_cert, args.type)
        if not manifest_file:
            print("Unable to create manifest")
            return STATUS_FAILURE
        print(f"Manifest created: '{manifest_file}'")
    elif args.action == "create-from-secure-element":
        manifest_file = create_manifest_from_secure_element(args.manifest, args.manifest_signer_cert, args.manifest_signer_key)
        if not manifest_file:
            print("Unable to create manifest")
            return STATUS_FAILURE
        print(f"Manifest created: '{manifest_file}'")
    elif args.action == "get-secure-element":
        element = get_secure_element(manifest, args.id)
        if not element:
            print("Secure element not found in manifest")
            return STATUS_FAILURE
        print("Secure element:")
        print(element)
    elif args.action == "list-secure-element-ids":
        elements = list_secure_element_ids(manifest)
        if not elements:
            print("No secure elements found in manifest")
            return STATUS_FAILURE
        print("Secure elements IDs:")
        for element in elements:
            print(element)
    elif args.action == "list-secure-elements":
        elements = list_secure_elements(manifest)
        if not elements:
            print("No secure elements found in manifest")
            return STATUS_FAILURE
        print("Secure elements in manifest:")
        for element in elements:
            print(element)
    elif args.action == "get-certificates":
        certificates = extract_certificates(manifest, cert_indexes=args.cert_index, outdir=args.outdir, unique_id=args.id)
        if not certificates:
            print("No certificates created")
            return STATUS_FAILURE
        print("Certificates extracted:")
        for certificate in certificates:
            print(certificate)
    else:
        pass
    return STATUS_SUCCESS

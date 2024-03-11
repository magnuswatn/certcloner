import logging
from io import BufferedReader
from typing import Any, TypeAlias

import click
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key as generate_ec_private_key
from cryptography.hazmat.primitives.asymmetric.padding import PSS, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    Certificate,
    CertificateBuilder,
    Extension,
    Name,
    ObjectIdentifier,
    SubjectKeyIdentifier,
    UnrecognizedExtension,
    load_der_x509_certificate,
    load_pem_x509_certificates,
)
from cryptography.x509.oid import ExtensionOID

from certcloner.__about__ import __version__

SUPPORTED_KEY_TYPES: TypeAlias = RSAPrivateKey | EllipticCurvePrivateKey

NETSCAPE_COMMENT_OID = ObjectIdentifier("2.16.840.1.113730.1.13")
# IA5String with length 44
COMMENT = b"\x16\x2cThis is a cloned cert created by certcloner."

logger = logging.getLogger(__name__)


class CertClonerError(Exception):
    pass


class InvalidInputError(CertClonerError):
    pass


class UnsupportedKeyError(InvalidInputError):
    pass


class UnsupportedSignatureInCertError(InvalidInputError):
    pass


class DuplicateSubjectError(InvalidInputError):
    pass


def clone_cert(
    org_cert: Certificate,
    cloned_keys: dict[Name, SUPPORTED_KEY_TYPES],
    *,
    include_comment: bool,
    update_key_identifiers: bool,
) -> tuple[Certificate, SUPPORTED_KEY_TYPES]:
    if logger.getEffectiveLevel() <= logging.DEBUG:
        logging.debug("Cloning %s", org_cert.subject.rfc4514_string())

    if (private_key := cloned_keys.get(org_cert.subject)) is None:
        org_pub_key = org_cert.public_key()

        if isinstance(org_pub_key, RSAPublicKey):
            private_key = generate_rsa_private_key(65537, org_pub_key.key_size)
        elif isinstance(org_pub_key, EllipticCurvePublicKey):
            private_key = generate_ec_private_key(org_pub_key.curve)
        else:
            exp_text = f"Unsupported key in cert {org_cert.subject.rfc4514_string()}: {type(org_pub_key).__name__}"
            raise UnsupportedKeyError(exp_text)
        cloned_keys[org_cert.subject] = private_key

    if (signing_key := cloned_keys.get(org_cert.issuer)) is None:
        # We don't have the full chain available. Just try to
        # create a key that matches what we know about the signing key.
        alg_params = org_cert.signature_algorithm_parameters
        signature_length = len(org_cert.signature)
        if isinstance(alg_params, PKCS1v15 | PSS):
            signing_key = generate_rsa_private_key(65537, signature_length * 8)
        elif isinstance(alg_params, ECDSA):
            if signature_length > 110:
                signing_key = generate_ec_private_key(SECP521R1())
            elif signature_length > 80:
                signing_key = generate_ec_private_key(SECP384R1())
            else:
                signing_key = generate_ec_private_key(SECP256R1())
        else:
            exp_text = (
                f"Unsupported signature algorithm in cert {org_cert.subject.rfc4514_string()}: "
                f"{org_cert.signature_algorithm_oid.dotted_string}"
            )
            raise UnsupportedSignatureInCertError(exp_text)
        cloned_keys[org_cert.issuer] = signing_key

    builder = (
        CertificateBuilder()
        .subject_name(org_cert.subject)
        .issuer_name(org_cert.issuer)
        .not_valid_before(org_cert.not_valid_before_utc)
        .not_valid_after(org_cert.not_valid_after_utc)
        .serial_number(org_cert.serial_number)
        .public_key(private_key.public_key())
    )

    ext: Extension
    for ext in org_cert.extensions:
        ext_val: Any
        if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER and update_key_identifiers:
            ext_val = SubjectKeyIdentifier.from_public_key(private_key.public_key())
        elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER and update_key_identifiers:
            ext_val = AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key())
        else:
            ext_val = ext.value
        builder = builder.add_extension(ext_val, ext.critical)

    if include_comment:
        netscape_comment_ext = UnrecognizedExtension(NETSCAPE_COMMENT_OID, COMMENT)
        try:
            builder = builder.add_extension(netscape_comment_ext, critical=False)
        except ValueError as ve:
            # Most likely already has a comment extension
            logger.warning("Failed to add comment extension to %s: %s", org_cert.subject.rfc4514_string(), ve)

    if not isinstance(hash_algo := org_cert.signature_hash_algorithm, SHA256 | SHA384 | SHA512):
        logger.debug("Replacing unsupported hash algorithm with SHA256 for %s", org_cert.subject.rfc4514_string())
        hash_algo = SHA256()

    rsa_padding = (
        org_cert.signature_algorithm_parameters if isinstance(org_cert.signature_algorithm_parameters, PSS) else None
    )

    certificate = builder.sign(private_key=signing_key, algorithm=hash_algo, rsa_padding=rsa_padding)

    return certificate, private_key


def clone_certs(
    original_certs: set[Certificate], *, include_comment: bool, update_key_identifiers: bool
) -> list[tuple[Certificate, SUPPORTED_KEY_TYPES]]:
    known_issuers: set[Name] = set()
    known_subjects_to_cert_map: dict[Name, Certificate] = {}

    for org_cert in original_certs:
        if (
            org_cert.subject in known_subjects_to_cert_map
            and org_cert.public_key() != known_subjects_to_cert_map[org_cert.subject].public_key()
        ):
            msg = f"Certificates with same subject, but different key in input: {org_cert.subject.rfc4514_string()}"
            raise DuplicateSubjectError(msg)
        known_subjects_to_cert_map[org_cert.subject] = org_cert
        known_issuers.add(org_cert.issuer)

    subject_to_cloned_key_map: dict[Name, SUPPORTED_KEY_TYPES] = {}
    cloned_certs: list[tuple[Certificate, SUPPORTED_KEY_TYPES]] = []
    processed_org_certs: list[Certificate] = []

    at_bottom = False
    while not at_bottom:
        at_bottom = True
        certs_to_clone = []
        for org_cert in original_certs:
            if not cloned_certs:
                # First iteration - let's clone the top level certs
                if org_cert.issuer == org_cert.subject or org_cert.issuer not in known_subjects_to_cert_map:
                    certs_to_clone.append(org_cert)
            elif org_cert.issuer in subject_to_cloned_key_map and org_cert not in processed_org_certs:
                certs_to_clone.append(org_cert)

        for org_cert in certs_to_clone:
            cloned_cert, priv_key = clone_cert(
                org_cert,
                subject_to_cloned_key_map,
                include_comment=include_comment,
                update_key_identifiers=update_key_identifiers,
            )
            cloned_certs.append((cloned_cert, priv_key))
            processed_org_certs.append(org_cert)

            if org_cert.subject in known_issuers:
                # This cert has issued another cert,
                # so we're not at the bottom just yet
                at_bottom = False

    return cloned_certs


def load_certs(input_data: list[bytes]) -> set[Certificate]:
    loaded_certs: set[Certificate] = set()
    for data in input_data:
        try:
            loaded_certs.update(load_pem_x509_certificates(data))
        except ValueError:
            loaded_certs.add(load_der_x509_certificate(data))

    return loaded_certs


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
@click.argument("files", type=click.File("rb"), nargs=-1)
@click.option("--no-comment", is_flag=True, help="Do not include a comment in the finished certs.")
@click.option("--keep-key-identifiers", is_flag=True, help="Keep the original key identifiers in the finished certs.")
def main(files: tuple[BufferedReader], *, no_comment: bool, keep_key_identifiers: bool):
    if not files:
        raise click.BadArgumentUsage("Must specify at least one cert")

    try:
        original_certs = load_certs([file.read() for file in files])
    except ValueError as error:
        raise click.ClickException("Failed to parse input as certificates") from error

    try:
        cloned_certs = clone_certs(
            original_certs,
            include_comment=not no_comment,
            update_key_identifiers=not keep_key_identifiers,
        )
    except InvalidInputError as error:
        raise click.ClickException(str(error)) from error

    for cert, key in cloned_certs:
        click.secho(f"# Subject: {cert.subject.rfc4514_string()}")
        click.secho(f"# Issuer: {cert.issuer.rfc4514_string()}")
        click.secho(cert.public_bytes(Encoding.PEM).decode())
        click.secho(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())


if __name__ == "__main__":
    main()

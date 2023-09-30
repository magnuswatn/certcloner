from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
    load_pem_private_key,
)
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    Certificate,
    CertificateBuilder,
    Extension,
    SubjectKeyIdentifier,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import ExtensionOID


def clone_cert(org_cert: Certificate, signing_key: RSAPrivateKey | None):
    assert isinstance(org_cert_pubkey := org_cert.public_key(), RSAPublicKey)
    private_key = generate_private_key(65537, org_cert_pubkey.key_size)

    if signing_key is None:
        assert org_cert.issuer == org_cert.subject
        signing_key = private_key

    builder = (
        CertificateBuilder()
        .subject_name(org_cert.subject)
        .issuer_name(org_cert.issuer)
        .not_valid_before(org_cert.not_valid_before)
        .not_valid_after(org_cert.not_valid_after)
        .serial_number(org_cert.serial_number)
        .public_key(private_key.public_key())
    )

    ext: Extension
    for ext in org_cert.extensions:
        if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            ext_val = SubjectKeyIdentifier.from_public_key(private_key.public_key())
        elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            ext_val = AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key())
        else:
            ext_val = ext.value
        builder = builder.add_extension(ext_val, ext.critical)

    certificate = builder.sign(
        private_key=signing_key,
        algorithm=SHA256(),
    )
    return certificate, private_key


def load_and_clone_cert(
    input_path: Path,
    private_key_path: Path | None,
) -> None:
    if not input_path.exists():
        raise Exception("input path no exists")

    if private_key_path is not None:
        if not private_key_path.exists():
            raise Exception("bad boi")
        priv_key = load_pem_private_key(private_key_path.read_bytes(), password=None)
    else:
        priv_key = None

    org_cert = load_pem_x509_certificate(input_path.read_bytes())

    if org_cert.issuer != org_cert.subject and priv_key is None:
        raise Exception("Need private key for non-self-signed cert")
    cloned_cert, private_key = clone_cert(org_cert, signing_key=priv_key)
    print(cloned_cert.public_bytes(Encoding.PEM).decode())
    print(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())


if __name__ == "__main__":
    load_and_clone_cert(Path("sha2_ee"), Path("fake_sha2_int_key.pem"))

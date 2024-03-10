from pathlib import Path
from secrets import choice

import pytest
from cryptography.x509 import Certificate, load_pem_x509_certificate

from tests import CERT_WITH_COMMENT_SERIAL

DSA_CERT_FILE = "cert_with_dsa_key.pem"
DSA_SIGNED_CERT_FILE = "cert_signed_with_dsa_key.pem"

CERTS_SIGNED_WITH_EC_CURVES = (
    "cert_signed_with_nist_p-224.pem",
    "cert_signed_with_nist_p-256.pem",
    "cert_signed_with_nist_p-384.pem",
    "cert_signed_with_nist_p-521.pem",
)


@pytest.fixture(scope="session")
def all_normal_cert_paths() -> list[Path]:
    return [
        path
        for path in Path("./tests/resources").iterdir()
        if path.name not in (DSA_CERT_FILE, DSA_SIGNED_CERT_FILE, *CERTS_SIGNED_WITH_EC_CURVES)
    ]


@pytest.fixture(scope="session")
def all_certs(all_normal_cert_paths: list[Path]) -> list[Certificate]:
    return [load_pem_x509_certificate(path.read_bytes()) for path in all_normal_cert_paths]


@pytest.fixture(scope="session")
def all_letsencrypt_certs(all_certs: list[Certificate]) -> set[Certificate]:
    return {cert for cert in all_certs if cert.serial_number != CERT_WITH_COMMENT_SERIAL}


@pytest.fixture
def random_cert(all_certs: list[Certificate]) -> Certificate:
    return choice(all_certs)


@pytest.fixture
def random_certs(all_certs: list[Certificate]) -> set[Certificate]:
    return {choice(all_certs) for _ in range(choice(range(1, len(all_certs))))}


@pytest.fixture
def dsa_cert() -> Certificate:
    return load_pem_x509_certificate(Path("./tests/resources").joinpath(DSA_CERT_FILE).read_bytes())


@pytest.fixture
def dsa_signed_cert() -> Certificate:
    return load_pem_x509_certificate(Path("./tests/resources").joinpath(DSA_SIGNED_CERT_FILE).read_bytes())


@pytest.fixture
def certs_signed_with_ec_curves() -> set[Certificate]:
    return {
        load_pem_x509_certificate(Path("./tests/resources").joinpath(cert_path).read_bytes())
        for cert_path in CERTS_SIGNED_WITH_EC_CURVES
    }

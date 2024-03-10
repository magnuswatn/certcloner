import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from certcloner.main import load_certs


@pytest.mark.parametrize("encoding", [Encoding.PEM, Encoding.DER])
def test_loading(random_cert: Certificate, *, encoding: Encoding) -> None:
    cert_bytes = random_cert.public_bytes(encoding)
    loaded_certs = load_certs([cert_bytes, cert_bytes])

    [loaded_cert] = loaded_certs
    assert loaded_cert == random_cert


def test_loading_duplicates(random_cert: Certificate) -> None:
    cert_bytes = random_cert.public_bytes(Encoding.DER)
    cert_bytes_pem = random_cert.public_bytes(Encoding.PEM)

    loaded_certs = load_certs([cert_bytes, cert_bytes_pem, cert_bytes])

    [loaded_cert] = loaded_certs
    assert loaded_cert == random_cert


def test_loading_combined_pems(random_certs: set[Certificate]) -> None:
    chosen_cert_pems = [cert.public_bytes(Encoding.PEM) for cert in random_certs]
    all_pem_certs = b"\n".join(chosen_cert_pems)
    loaded_certs = load_certs([all_pem_certs])
    assert loaded_certs == random_certs

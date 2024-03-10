import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from certcloner.main import main


def test_missing_cert():
    runner = CliRunner()
    result = runner.invoke(main, ["ds"])
    assert result.exit_code == 2
    assert "No such file or directory" in result.output


def test_clone_certs(all_normal_cert_paths: list[Path]):
    runner = CliRunner()
    result = runner.invoke(main, [str(path) for path in all_normal_cert_paths])
    assert result.exit_code == 0


def test_no_certs_specified_gives_error_message():
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code == 2
    assert "Must specify at least one cert" in result.output


def test_clone_certs_bad_certificate_gives_error_message():
    with tempfile.NamedTemporaryFile() as fp:
        fp.write(b"")
        fp.seek(0)

        runner = CliRunner()
        result = runner.invoke(main, [fp.name])
        assert result.exit_code == 2
        assert "Failed to parse input as certificates" in result.output


@pytest.mark.parametrize("encoding", [Encoding.DER, Encoding.PEM])
def test_invalid_cert_gives_error_message(dsa_cert: Certificate, encoding: Encoding):
    with tempfile.NamedTemporaryFile() as fp:
        fp.write(dsa_cert.public_bytes(encoding))
        fp.seek(0)
        runner = CliRunner()
        result = runner.invoke(main, [fp.name])
        assert result.exit_code == 2
        assert " Unsupported key in cert CN=DSA key: DSAPublicKey" in result.output

import logging
from collections import defaultdict
from secrets import choice

import pytest
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    Certificate,
    Name,
    SubjectKeyIdentifier,
)
from cryptography.x509.extensions import ExtensionNotFound
from OpenSSL.crypto import X509, X509Store, X509StoreContext, X509StoreFlags  # type: ignore

from certcloner.main import (
    NETSCAPE_COMMENT_OID,
    DuplicateSubjectError,
    UnsupportedKeyError,
    UnsupportedSignatureInCertError,
    clone_certs,
)
from tests import CERT_WITH_COMMENT_SERIAL, EE_SERIAL_NUMBER

X509_V_FLAG_NO_CHECK_TIME = 0x200000


@pytest.mark.parametrize("include_comment", [True, False])
@pytest.mark.parametrize("update_key_identifiers", [True, False])
def test_clone_cross_signed_certs_reuses_same_key(
    all_letsencrypt_certs: set[Certificate],
    caplog: pytest.LogCaptureFixture,
    *,
    include_comment: bool,
    update_key_identifiers: bool,
) -> None:
    """
    We should re-use the key for the cloned cert, if we have cross-signed certs in the input.
    """
    # pure for the coverage...
    caplog.set_level(logging.DEBUG)

    certs_sets: dict[Name, set[Certificate]] = defaultdict(set)
    for cert in all_letsencrypt_certs:
        certs_sets[cert.subject].add(cert)

    cross_signed_cert_sets = [cert_set for cert_set in certs_sets.values() if len(cert_set) > 1]
    for cert_set in cross_signed_cert_sets:
        cloned_certs = clone_certs(
            cert_set,
            include_comment=include_comment,
            update_key_identifiers=update_key_identifiers,
        )
        assert all(cloned_cert_and_key[1] == cloned_certs[0][1] for cloned_cert_and_key in cloned_certs)


@pytest.mark.parametrize("include_comment", [True, False])
@pytest.mark.parametrize("update_key_identifiers", [True, False])
def test_cloning_creats_valid_chains(
    all_letsencrypt_certs: set[Certificate], *, include_comment: bool, update_key_identifiers: bool
) -> None:
    cloned_certs_and_keys = clone_certs(
        all_letsencrypt_certs,
        include_comment=include_comment,
        update_key_identifiers=update_key_identifiers,
    )

    cloned_certs = [cert_and_key[0] for cert_and_key in cloned_certs_and_keys]

    assert len(cloned_certs) == len(all_letsencrypt_certs)

    cloned_root_certs = [X509.from_cryptography(cert) for cert in cloned_certs if cert.subject == cert.issuer]
    cloned_chain = [
        X509.from_cryptography(cert)
        for cert in cloned_certs
        if cert.subject != cert.issuer and cert.serial_number != EE_SERIAL_NUMBER
    ]
    [cloned_ee_cert] = [X509.from_cryptography(cert) for cert in cloned_certs if cert.serial_number == EE_SERIAL_NUMBER]

    # Verify that the new chain is good
    for cloned_root_cert in cloned_root_certs:
        x509_store = X509Store()
        x509_store.set_flags(X509_V_FLAG_NO_CHECK_TIME | X509StoreFlags.X509_STRICT | X509StoreFlags.CHECK_SS_SIGNATURE)
        x509_store.add_cert(cloned_root_cert)
        x509_context = X509StoreContext(x509_store, cloned_ee_cert, cloned_chain)

        verified_chain = x509_context.get_verified_chain()
        last_authority_key_identifier: AuthorityKeyIdentifier | None = None
        last_cert: Certificate | None = None
        for openssl_verified_cert in verified_chain:
            verified_cert = openssl_verified_cert.to_cryptography()

            if last_cert is not None:
                last_cert.verify_directly_issued_by(verified_cert)

            try:
                authority_key_identifier = verified_cert.extensions.get_extension_for_class(AuthorityKeyIdentifier)
            except ExtensionNotFound:
                authority_key_identifier = None

            subject_key_identifier = verified_cert.extensions.get_extension_for_class(SubjectKeyIdentifier)

            if last_authority_key_identifier is not None and subject_key_identifier is not None:
                assert (
                    AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key_identifier.value)
                    == last_authority_key_identifier
                )

            ski_matches_key = (
                SubjectKeyIdentifier.from_public_key(verified_cert.public_key()) == subject_key_identifier.value
            )
            assert ski_matches_key if update_key_identifiers else not ski_matches_key

            last_cert = verified_cert
            last_authority_key_identifier = authority_key_identifier.value if authority_key_identifier else None


@pytest.mark.parametrize("include_comment", [True, False])
def test_cloning_comment_handling(all_letsencrypt_certs: set[Certificate], *, include_comment: bool) -> None:
    one_cert = choice(list(all_letsencrypt_certs))

    cloned_certs_and_keys = clone_certs({one_cert}, include_comment=include_comment, update_key_identifiers=True)

    assert len(cloned_certs_and_keys) == 1
    cloned_cert = cloned_certs_and_keys[0][0]
    try:
        netscape_comment_exception = cloned_cert.extensions.get_extension_for_oid(NETSCAPE_COMMENT_OID)
    except ExtensionNotFound:
        assert not include_comment
        return
    assert include_comment

    assert netscape_comment_exception.critical is False
    comment = netscape_comment_exception.value.public_bytes()

    assert comment[0] == 22  # IA5String
    assert comment[1] == len(comment) - 2
    assert comment[2:] == b"This is a cloned cert created by certcloner."


def test_cloning_cert_with_existing_comment(all_certs: list[Certificate]) -> None:
    [cert_with_comment] = [cert for cert in all_certs if cert.serial_number == CERT_WITH_COMMENT_SERIAL]

    cloned_certs_and_keys = clone_certs({cert_with_comment}, include_comment=True, update_key_identifiers=True)

    assert len(cloned_certs_and_keys) == 1
    cloned_cert = cloned_certs_and_keys[0][0]

    netscape_comment_exception = cloned_cert.extensions.get_extension_for_oid(NETSCAPE_COMMENT_OID)

    assert netscape_comment_exception.critical is False
    comment = netscape_comment_exception.value.public_bytes()

    assert comment[0] == 22  # IA5String
    assert comment[1] == len(comment) - 2
    assert comment[2:] == b"This is an existing comment."


@pytest.mark.parametrize("include_comment", [True, False])
@pytest.mark.parametrize("update_key_identifiers", [True, False])
def test_cloning_random_selection(
    random_certs: set[Certificate], *, include_comment: bool, update_key_identifiers: bool
) -> None:
    # All combinations of certs should be clonable
    cloned_certs = clone_certs(
        random_certs,
        include_comment=include_comment,
        update_key_identifiers=update_key_identifiers,
    )
    assert len(cloned_certs) == len(random_certs)


@pytest.mark.parametrize("include_comment", [True, False])
@pytest.mark.parametrize("update_key_identifiers", [True, False])
def test_cloning_cert_signed_with_ec_curves(
    certs_signed_with_ec_curves: set[Certificate], *, include_comment: bool, update_key_identifiers: bool
) -> None:
    for cert in certs_signed_with_ec_curves:
        clone_certs(
            {cert},
            include_comment=include_comment,
            update_key_identifiers=update_key_identifiers,
        )


def test_cloning_certs_with_duplicate_subject(random_cert: Certificate) -> None:
    [(cloned_cert, _)] = clone_certs({random_cert}, include_comment=True, update_key_identifiers=True)

    with pytest.raises(DuplicateSubjectError):
        clone_certs({random_cert, cloned_cert}, include_comment=True, update_key_identifiers=True)


@pytest.mark.parametrize("include_comment", [True, False])
@pytest.mark.parametrize("update_key_identifiers", [True, False])
def test_cloning_cert_with_dsa_key(
    dsa_cert: Certificate, *, include_comment: bool, update_key_identifiers: bool
) -> None:
    with pytest.raises(UnsupportedKeyError):
        clone_certs(
            {dsa_cert},
            include_comment=include_comment,
            update_key_identifiers=update_key_identifiers,
        )


@pytest.mark.parametrize("include_comment", [True, False])
@pytest.mark.parametrize("update_key_identifiers", [True, False])
def test_cloning_cert_signed_with_dsa_key(
    dsa_signed_cert: Certificate, *, include_comment: bool, update_key_identifiers: bool
) -> None:
    with pytest.raises(UnsupportedSignatureInCertError):
        clone_certs(
            {dsa_signed_cert},
            include_comment=include_comment,
            update_key_identifiers=update_key_identifiers,
        )

from datetime import datetime, timedelta

import pytest

from ca_key_cert_validator.generators import gen_key, build_and_sign_certificate
from ca_key_cert_validator.savers import private_key_to_pem, certificate_to_pem, certificate_to_bytes
from ca_key_cert_validator import validate_certificate_from_bytes, CertificateIsNotCAValidationError


def test_case_1_valid_pair_of_key_and_cert():
    key = gen_key()
    private_key_to_pem(key, 'test_key_1.key')

    cert = build_and_sign_certificate(key)
    certificate_to_pem(cert, 'test_cert_1.crt')


def test_case_2_expired_in_less_31_days():
    key = gen_key()
    private_key_to_pem(key, 'test_key_2.key')

    cert = build_and_sign_certificate(key, days_valid=7)
    certificate_to_pem(cert, 'test_cert_2.crt')


def test_case_3_cert_is_already_expired():
    key = gen_key()
    private_key_to_pem(key, 'test_key_3.key')

    cert = build_and_sign_certificate(
        key,
        not_valid_before=datetime.now() - timedelta(days=31),
        not_valid_after=datetime.now() - timedelta(days=1)
    )
    certificate_to_pem(cert, 'test_cert_3.crt')


def test_case_1_valid_pair_of_key_and_cert_password():
    key = gen_key()
    private_key_to_pem(key, 'test_key_1_password.key', password=b'password')

    cert = build_and_sign_certificate(key)
    certificate_to_pem(cert, 'test_cert_1_password.crt')


def test_case_2_expired_in_less_31_days_password():
    key = gen_key()
    private_key_to_pem(key, 'test_key_2_password.key', password=b'password')

    cert = build_and_sign_certificate(key, days_valid=7)
    certificate_to_pem(cert, 'test_cert_2_password.crt')


def test_case_3_cert_is_already_expired_password():
    key = gen_key()
    private_key_to_pem(key, 'test_key_3_password.key', password=b'password')

    cert = build_and_sign_certificate(
        key,
        not_valid_before=datetime.now() - timedelta(days=31),
        not_valid_after=datetime.now() - timedelta(days=1)
    )
    certificate_to_pem(cert, 'test_cert_3_password.crt')


def test_case_4_cert_is_not_ca():
    key = gen_key()
    private_key_to_pem(key, 'test_key_4_not_ca.key')

    cert = build_and_sign_certificate(key, is_ca=False)
    certificate_to_pem(cert, 'test_cert_4_not_ca.crt')

    with pytest.raises(CertificateIsNotCAValidationError):
        validate_certificate_from_bytes(
            certificate_to_bytes(cert),
            key
        )

def test_case_5_cert_signed_by_not_the_same_key():
    key = gen_key()
    private_key_to_pem(key, 'test_key_5_signed_by_not_the_same_key.key')

    ca_key = gen_key()
    private_key_to_pem(ca_key, 'test_key_5_signed_by_not_the_same_key_ca.key')

    cert = build_and_sign_certificate(key, ca_key=ca_key)
    certificate_to_pem(cert, 'test_cert_5_signed_by_not_the_same_key.crt')


def test_case_6_cert_signed_by_not_the_same_key_password():
    key = gen_key()
    private_key_to_pem(key, 'test_key_6_signed_by_not_the_same_key_password.key', password=b'password')

    ca_key = gen_key()
    private_key_to_pem(ca_key, 'test_key_6_signed_by_not_the_same_key_password_ca.key', password=b'password')

    cert = build_and_sign_certificate(key, ca_key=ca_key)
    certificate_to_pem(cert, 'test_cert_6_signed_by_not_the_same_key_password.crt')

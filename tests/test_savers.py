import pytest

from ca_key_cert_validator.generators import gen_key, build_and_sign_certificate
from ca_key_cert_validator.savers import (
    private_key_to_bytes, private_key_to_bytes_with_password, certificate_to_bytes
)

from ca_key_cert_validator.loaders import load_key_from_bytes, load_cert_from_bytes
from ca_key_cert_validator import expections


def test_without_password():
    key = gen_key()
    assert key
    assert key.key_size == 2048

    data = private_key_to_bytes(key)
    assert data
    assert isinstance(data, bytes)

    loaded_key = load_key_from_bytes(data)
    assert loaded_key

    assert key.key_size == loaded_key.key_size
    assert key.public_key() == loaded_key.public_key()


def test_with_password():
    password = b'password'
    key = gen_key()
    assert key
    assert key.key_size == 2048

    data = private_key_to_bytes_with_password(key, password)
    assert data
    assert isinstance(data, bytes)

    loaded_key = load_key_from_bytes(data, password)
    assert loaded_key

    assert key.key_size == loaded_key.key_size
    assert key.public_key() == loaded_key.public_key()

    # incorrect password case
    with pytest.raises(expections.KeyIncorrectPasswordValidationError):
        load_key_from_bytes(data, b'wrong_password')


def test_loading_key_with_password_when_should_not():
    key = gen_key()
    assert key
    assert key.key_size == 2048

    data = private_key_to_bytes(key)
    assert data
    assert isinstance(data, bytes)

    with pytest.raises(expections.KeyIsNotEncryptedValidationError):
        load_key_from_bytes(data, password=b'some_password')


def test_loading_key_with_no_password_when_should():
    key = gen_key()

    data = private_key_to_bytes_with_password(key, b'password')
    assert isinstance(data, bytes)

    with pytest.raises(expections.KeyIsEncryptedValidationError):
        load_key_from_bytes(data)


def test_loading_key_in_invalid_format():
    with pytest.raises(expections.KeyInvalidFormatValidationError):
        load_key_from_bytes(b'invalid_data')


def test_loading_cert_in_valid_format():
    key = gen_key()
    cert = build_and_sign_certificate(key)
    data = certificate_to_bytes(cert)
    cert_loaded = load_cert_from_bytes(data)
    assert cert_loaded.serial_number == cert.serial_number


def test_loading_cert_in_invalid_format():
    with pytest.raises(expections.CertificateInvalidFormatValidationError):
        load_cert_from_bytes(b'invalid_data')

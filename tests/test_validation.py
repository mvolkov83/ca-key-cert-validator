from ca_key_cert_validator.generators import gen_key, build_and_sign_certificate
from ca_key_cert_validator.savers import private_key_to_bytes, certificate_to_bytes

from ca_key_cert_validator import validate_key_from_bytes, validate_certificate_from_bytes


def test_valid_flow():
    key = gen_key()
    key_bytes = private_key_to_bytes(key)

    cert = build_and_sign_certificate(key)
    cert_bytes = certificate_to_bytes(cert)

    key_validated = validate_key_from_bytes(key_bytes)
    assert key_validated.key.private_numbers() == key.private_numbers()

    cert_validated = validate_certificate_from_bytes(cert_bytes, key_validated.key)
    assert cert_validated.certificate.tbs_certificate_bytes == cert.tbs_certificate_bytes
    assert cert_validated.certificate.signature == cert.signature

from ca_key_cert_validator.generators import gen_key, build_and_sign_certificate


def test_cert_1():
    key = gen_key()
    assert key
    assert key.key_size == 2048

    cert = build_and_sign_certificate(key)
    assert cert

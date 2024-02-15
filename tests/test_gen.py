from ca_key_cert_validator.generators import gen_key
from ca_key_cert_validator.savers import private_key_to_bytes


def test_gen_key():
    key = gen_key()
    assert key
    assert key.key_size == 2048
    key = gen_key(4096)
    assert key
    assert key.key_size == 4096

    data = private_key_to_bytes(key)
    assert data
    assert isinstance(data, bytes)

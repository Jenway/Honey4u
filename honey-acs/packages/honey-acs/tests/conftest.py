import honey_native
import pytest


@pytest.fixture
def signing_keys() -> list[honey_native.ThresholdSignatureRuntime]:
    n = 4
    f = 1
    pk_bytes, sk_bytes_list = honey_native.sig_generate(n, f + 1)
    return [honey_native.ThresholdSignatureRuntime.from_bytes(pk_bytes, sk) for sk in sk_bytes_list]

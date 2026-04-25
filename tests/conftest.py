import honey_native
import pytest
from honey_acs.runtime.native import NativeThresholdSignatureRuntime


@pytest.fixture
def signing_keys() -> list[NativeThresholdSignatureRuntime]:
    N = 4
    f = 1
    pk, sks = honey_native.sig_generate(N, f + 1)
    pk_bytes = pk.to_bytes()
    return [NativeThresholdSignatureRuntime.from_bytes(pk_bytes, sk.to_bytes()) for sk in sks]

import honey_native
import pytest
from honey_acs.crypto.sig import PrivateShare as SigPrivateMaterial
from honey_acs.crypto.sig import PublicKey as SigPublicMaterial
from honey_acs.crypto.sig import generate as sig_generate


@pytest.fixture
def signing_keys() -> tuple[SigPublicMaterial, list[SigPrivateMaterial]]:
    N = 4
    f = 1
    pk, sks = sig_generate(N, f + 1, seed=None)
    return pk, sks


@pytest.fixture
def encryption_keys() -> tuple[honey_native.PkePublicKey, list[honey_native.PkePrivateShare]]:
    N = 4
    f = 1
    pk, sks = honey_native.pke_generate(N, f + 1)
    return pk, sks

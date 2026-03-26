import pytest

from honey.crypto.pke import PrivateShare as EncPrivateMaterial
from honey.crypto.pke import PublicKey as EncPublicMaterial
from honey.crypto.pke import generate as enc_generate
from honey.crypto.sig import PrivateShare as SigPrivateMaterial
from honey.crypto.sig import PublicKey as SigPublicMaterial
from honey.crypto.sig import generate as sig_generate


@pytest.fixture
def signing_keys() -> tuple[SigPublicMaterial, list[SigPrivateMaterial]]:
    N = 4
    f = 1
    pk, sks = sig_generate(N, f + 1, seed=None)
    return pk, sks


@pytest.fixture
def encryption_keys() -> tuple[EncPublicMaterial, list[EncPrivateMaterial]]:
    N = 4
    f = 1
    pk, sks = enc_generate(N, f + 1)
    return pk, sks

import pytest

from crypto.threshsig import SigPrivateMaterial, SigPublicMaterial, dealer


@pytest.fixture
def signing_keys() -> tuple[SigPublicMaterial, list[SigPrivateMaterial]]:
    """Generate threshold signature keys for N=4, f=1.

    Returns:
        tuple: (pk, sks) where pk is the public key and sks is a list of N private keys
    """
    N = 4
    f = 1
    # Generate (f+1, N) threshold signature keys
    # Use a fixed seed for reproducible test results
    pk, sks = dealer(N, f + 1, seed=None)
    return pk, sks

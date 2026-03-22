"""Threshold Signature Scheme (BLS-based)

Implements Boldyreva's threshold signature scheme using BLS cryptography.
All cryptographic operations are performed in the Rust native module.

Reference: https://eprint.iacr.org/2002/118.pdf
"""

from __future__ import annotations

try:
    import honey_native
except Exception as err:
    print(err)
    exit(-1)


class _Element:
    """Wrapper for serialized cryptographic elements."""

    __slots__ = ("data",)

    def __init__(self, data: bytes):
        self.data = bytes(data)

    def initPP(self):
        return None

    def __getstate__(self):
        return self.data

    def __setstate__(self, data):
        self.data = bytes(data)


def _ensure_bytes(x):
    """Convert an Element or bytes-like to bytes."""
    if isinstance(x, _Element):
        return x.data
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    raise TypeError(f"expected bytes-like or _Element, got {type(x)!r}")


def serialize(g):
    """Serialize an element to bytes."""
    return _ensure_bytes(g)


def deserialize0(g):
    """Deserialize signature/scalar element."""
    return _Element(g)


def deserialize1(g):
    """Deserialize G2 element."""
    return _Element(g)


def deserialize2(g):
    """Deserialize G2 element (verification key)."""
    return _Element(g)


class TBLSPublicKey:
    """Threshold BLS Public Key

    Handles signature verification and share combination.
    """

    def __init__(self, players: int, k: int, params_bin: bytes):
        """Initialize TBLS public key.

        Args:
            players: Total number of players
            k: Threshold for signature reconstruction
            params_bin: Serialized public parameters
        """
        self.l = players
        self.k = k
        self.params_bin = params_bin
        # Create a dummy signer just for verification
        # Use player_id=0 and a dummy share (won't be used for verification)
        self._verifier = None
        self._init_verifier()

    def _init_verifier(self):
        """Initialize a verifier signer (used only for verify_share and combine_shares)."""
        try:
            # Use player_id=1 (1-based for Rust) and empty bytes as dummy share
            # The key point is that verify_share and combine_shares only use public_params
            dummy_share = b"\x00" * 32  # Create a dummy share that might work for deserialization
            self._verifier = honey_native.ThresholdSigner(1, self.params_bin, dummy_share)
        except Exception:
            # If this fails, we'll try on-demand creation
            self._verifier = None

    def __getstate__(self):
        return {
            "l": self.l,
            "k": self.k,
            "params_bin": self.params_bin,
        }

    def __setstate__(self, d):
        self.l = d["l"]
        self.k = d["k"]
        self.params_bin = d["params_bin"]

    def verify_share(self, sig_bin: bytes, player_id: int, msg: bytes) -> bool:
        """Verify a signature share.

        Args:
            sig_bin: Serialized signature share
            player_id: ID of the signing player (0-based)
            msg: Message that was signed

        Returns:
            True if signature is valid
        """
        signer = honey_native.ThresholdSigner(player_id + 1, self.params_bin, sig_bin)
        return signer.verify_share(player_id + 1, sig_bin, msg)

    def combine_shares(self, sigs: dict[int, bytes], msg: bytes) -> bytes:
        """Combine signature shares into a full signature.

        Args:
            sigs: Mapping from player_id (0-based) to signature bytes
            msg: Original message

        Returns:
            Serialized combined signature
        """
        share_vec = [(j + 1, _ensure_bytes(sig)) for j, sig in sigs.items()]
        # Create a temporary signer just to access combine_shares API
        # Use the first signature to initialize
        first_id = min(sigs.keys()) + 1
        any_sig = _ensure_bytes(list(sigs.values())[0])
        signer = honey_native.ThresholdSigner(first_id, self.params_bin, any_sig)
        return signer.combine_shares(share_vec, msg)


class TBLSPrivateKey(TBLSPublicKey):
    """Threshold BLS Private Key

    Extends public key with signing capability.
    """

    def __init__(self, players: int, k: int, params_bin: bytes, share_bin: bytes, i: int):
        """Initialize TBLS private key.

        Args:
            players: Total number of players
            k: Threshold for signature reconstruction
            params_bin: Serialized public parameters
            share_bin: Serialized private key share
            i: Player index (0-based)
        """
        super().__init__(players, k, params_bin)
        self.share_bin = share_bin
        self.i = i

    def __getstate__(self):
        d = super().__getstate__()
        d["share_bin"] = self.share_bin
        d["i"] = self.i
        return d

    def __setstate__(self, d):
        super().__setstate__(d)
        self.share_bin = d["share_bin"]
        self.i = d["i"]

    def sign(self, msg: bytes) -> bytes:
        """Sign a message with the private key share.

        Args:
            msg: Message to sign

        Returns:
            Serialized partial signature
        """
        signer = honey_native.ThresholdSigner(self.i + 1, self.params_bin, self.share_bin)
        return signer.sign(msg)


def dealer(
    players: int, threshold: int, seed: None = None
) -> tuple[TBLSPublicKey, list[TBLSPrivateKey]]:
    """Generate threshold signature keys for a group of players.

    Args:
        players: Total number of players
        threshold: Threshold for signature reconstruction (e.g., f+1)
        seed: Unused (for compatibility with old API)

    Returns:
        (public_key, private_keys)
        - public_key: TBLSPublicKey for verification
        - private_keys: List of TBLSPrivateKey for each player
    """
    params_bin, shares_bin = honey_native.sig_generate_keys(players, threshold)

    pub_key = TBLSPublicKey(players, threshold, params_bin)
    priv_keys = [
        TBLSPrivateKey(players, threshold, params_bin, shares_bin[i], i) for i in range(players)
    ]

    return pub_key, priv_keys

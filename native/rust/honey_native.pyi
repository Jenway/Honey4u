"""
Type stubs for honey_native Rust module.
Provides threshold signature and public key encryption via BLS cryptography.
"""

def sig_generate_keys(players: int, threshold: int) -> tuple[bytes, list[bytes]]:
    """
    Offline generation of threshold signature keys.

    Args:
        players: Total number of parties
        threshold: Threshold for signature reconstruction

    Returns:
        A tuple of (public_params, list_of_private_shares)
        - public_params: Serialized public parameters (bytes)
        - list_of_private_shares: List of serialized private key shares (list[bytes])
    """
    ...

def pke_generate_keys(players: int, threshold: int) -> tuple[bytes, bytes, list[bytes]]:
    """
    Offline generation of threshold PKE keys.

    Args:
        players: Total number of parties
        threshold: Threshold for decryption reconstruction

    Returns:
        A tuple of (public_params, master_public_key, list_of_private_shares)
        - public_params: Serialized public parameters (bytes)
        - master_public_key: Serialized master public key (bytes)
        - list_of_private_shares: List of serialized private key shares (list[bytes])
    """
    ...

def pke_encrypt(pk_bin: bytes, msg: bytes) -> bytes:
    """
    Encrypt a message under a public key.

    Args:
        pk_bin: Serialized public key (bytes)
        msg: Message to encrypt (must be exactly 32 bytes)

    Returns:
        Serialized ciphertext (bytes)

    Raises:
        ValueError: If message is not exactly 32 bytes
    """
    ...

def pke_verify_ciphertext(pk_bin: bytes, ct_bin: bytes) -> bool:
    """
    Verify a serialized threshold PKE ciphertext.

    Args:
        pk_bin: Serialized public key (bytes)
        ct_bin: Serialized ciphertext (bytes)

    Returns:
        True if ciphertext is valid under the key, False otherwise
    """
    ...

def pke_partial_open(sk_bin: bytes, ct_bin: bytes) -> bytes:
    """
    Create a serialized decryption share for a ciphertext.

    Args:
        sk_bin: Serialized private key share (bytes)
        ct_bin: Serialized ciphertext (bytes)

    Returns:
        Serialized decryption share (bytes)
    """
    ...

def pke_open(pk_bin: bytes, ct_bin: bytes, shares_bin: list[bytes]) -> bytes:
    """
    Combine decryption shares and recover the plaintext.

    Args:
        pk_bin: Serialized public key (bytes)
        ct_bin: Serialized ciphertext (bytes)
        shares_bin: Serialized decryption shares (list[bytes])

    Returns:
        Decrypted plaintext bytes
    """
    ...

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt data using AES-GCM.

    Args:
        key: Symmetric key bytes
        plaintext: Plaintext bytes

    Returns:
        Ciphertext bytes with nonce and tag included
    """
    ...

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt data encrypted by aes_encrypt.

    Args:
        key: Symmetric key bytes
        ciphertext: Ciphertext bytes

    Returns:
        Decrypted plaintext bytes
    """
    ...

def save_sig_keys(output_dir: str, params_bin: bytes, shares_bin: list[bytes]) -> None:
    """
    Save threshold signature keys to disk.

    Args:
        output_dir: Directory to save keys to
        params_bin: Serialized public parameters
        shares_bin: List of serialized private key shares

    Raises:
        ValueError: If directory creation or file writing fails
    """
    ...

def save_pke_keys(
    output_dir: str, params_bin: bytes, mpk_bin: bytes, shares_bin: list[bytes]
) -> None:
    """
    Save threshold PKE keys to disk.

    Args:
        output_dir: Directory to save keys to
        params_bin: Serialized public parameters
        mpk_bin: Serialized master public key
        shares_bin: List of serialized private key shares

    Raises:
        ValueError: If directory creation or file writing fails
    """
    ...

def load_sig_keys(key_dir: str) -> tuple[bytes, list[bytes]]:
    """
    Load threshold signature keys from disk.

    Args:
        key_dir: Directory to load keys from

    Returns:
        A tuple of (public_params, list_of_private_shares)
        - public_params: Serialized public parameters (bytes)
        - list_of_private_shares: List of serialized private key shares (list[bytes])

    Raises:
        ValueError: If files not found or reading fails
    """
    ...

def load_pke_keys(key_dir: str) -> tuple[bytes, bytes, list[bytes]]:
    """
    Load threshold PKE keys from disk.

    Args:
        key_dir: Directory to load keys from

    Returns:
        A tuple of (public_params, master_public_key, list_of_private_shares)
        - public_params: Serialized public parameters (bytes)
        - master_public_key: Serialized master public key (bytes)
        - list_of_private_shares: List of serialized private key shares (list[bytes])

    Raises:
        ValueError: If files not found or reading fails
    """
    ...

class ThresholdSigner:
    """A resident pointer to the node's threshold signature state."""

    def __init__(self, player_id: int, params_bin: bytes, share_bin: bytes) -> None:
        """
        Initialize a threshold signer.

        Args:
            player_id: ID of this player
            params_bin: Serialized public parameters
            share_bin: Serialized private key share for this player

        Raises:
            ValueError: If deserialization fails
        """
        ...

    @property
    def player_id(self) -> int:
        """Get the player ID."""
        ...

    def sign(self, msg: bytes) -> bytes:
        """
        Sign a message using the resident private share.

        Args:
            msg: Message to sign

        Returns:
            Serialized partial signature (bytes)
        """
        ...

    def verify_share(self, player_id: int, sig_bytes: bytes, msg: bytes) -> bool:
        """
        Verify another node's signature share.

        Args:
            player_id: ID of the signing player
            sig_bytes: Serialized signature share
            msg: Original message that was signed

        Returns:
            True if signature is valid, False otherwise
        """
        ...

    def combine_shares(self, shares: list[tuple[int, bytes]], msg: bytes) -> bytes:
        """
        Combine multiple valid signature shares into a full signature.

        Args:
            shares: List of (player_id, signature_bytes) tuples
            msg: Original message that was signed

        Returns:
            Serialized combined signature (bytes)

        Raises:
            ValueError: If signature combination or verification fails
        """
        ...

class ThresholdDecryptor:
    """A resident pointer to the node's threshold decryption state."""

    def __init__(self, player_id: int, params_bin: bytes, share_bin: bytes) -> None:
        """
        Initialize a threshold decryptor.

        Args:
            player_id: ID of this player
            params_bin: Serialized public parameters
            share_bin: Serialized private key share for this player

        Raises:
            ValueError: If deserialization fails
        """
        ...

    @property
    def player_id(self) -> int:
        """Get the player ID."""
        ...

    def decrypt_share(self, ct_bin: bytes) -> bytes:
        """
        Create a decryption share for a ciphertext.

        Args:
            ct_bin: Serialized ciphertext

        Returns:
            Serialized partial decryption share (bytes)

        Raises:
            ValueError: If deserialization fails
        """
        ...

    def verify_share(self, player_id: int, ct_bin: bytes, share_bin: bytes) -> bool:
        """
        Verify a decryption share.

        Args:
            player_id: ID of the decrypting player
            ct_bin: Serialized ciphertext
            share_bin: Serialized decryption share

        Returns:
            True if decryption share is valid, False otherwise
        """
        ...

    def combine_shares(self, ct_bin: bytes, shares_bin: list[bytes]) -> bytes:
        """
        Combine multiple decryption shares to decrypt a ciphertext.

        Args:
            ct_bin: Serialized ciphertext
            shares_bin: List of serialized decryption shares

        Returns:
            Decrypted message (32 bytes)

        Raises:
            ValueError: If deserialization or decryption fails
        """
        ...

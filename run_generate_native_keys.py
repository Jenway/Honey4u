import honey_native


def generate_and_save_keys(players: int, threshold: int, output_dir: str):
    """
    Generate native Threshold Signatures (sPK, sSKs) and PKE keys (ePK, eSKs),
    and save them directly via Rust into the specified directory.
    """
    print(f"Generating native keys for {players} players, threshold {threshold}...")

    sig_pk, sig_shares = honey_native.sig_generate(players, threshold)
    pke_pk, pke_shares = honey_native.pke_generate(players, threshold)

    sig_params = sig_pk.to_bytes()
    sig_share_bins = [share.to_bytes() for share in sig_shares]
    pke_params = pke_pk.to_bytes()
    pke_mpk = pke_pk.master_public_key_bytes()
    pke_share_bins = [share.to_bytes() for share in pke_shares]

    print(f"Saving generated keys to {output_dir} via Rust...")
    honey_native.save_sig_keys(output_dir, sig_params, sig_share_bins)
    honey_native.save_pke_keys(output_dir, pke_params, pke_mpk, pke_share_bins)

    print(f"Native Threshold keys successfully saved to {output_dir}")


def load_sig_keys(key_dir: str):
    """
    Load threshold signature keys from disk.

    Args:
        key_dir: Directory containing saved signature keys

    Returns:
        A tuple of (sig_params, sig_shares) where:
        - sig_params: Serialized public parameters (bytes)
        - sig_shares: List of serialized private key shares (list[bytes])
    """
    print(f"Loading signature keys from {key_dir}...")
    sig_params, sig_shares = honey_native.load_sig_keys(key_dir)
    print(f"Successfully loaded signature keys: params + {len(sig_shares)} shares")
    return sig_params, sig_shares


def load_pke_keys(key_dir: str):
    """
    Load threshold PKE keys from disk.

    Args:
        key_dir: Directory containing saved PKE keys

    Returns:
        A tuple of (pke_params, pke_mpk, pke_shares) where:
        - pke_params: Serialized public parameters (bytes)
        - pke_mpk: Serialized master public key (bytes)
        - pke_shares: List of serialized private key shares (list[bytes])
    """
    print(f"Loading PKE keys from {key_dir}...")
    pke_params, pke_mpk, pke_shares = honey_native.load_pke_keys(key_dir)
    print(f"Successfully loaded PKE keys: params + mpk + {len(pke_shares)} shares")
    return pke_params, pke_mpk, pke_shares


def run():
    import argparse

    parser = argparse.ArgumentParser(description="Save native threshold keys into fspath")
    parser.add_argument("--N", required=True, type=int, help="Total number of parties")
    parser.add_argument("--t", required=True, type=int, help="Threshold (e.g., f+1)")
    parser.add_argument(
        "--dir", required=False, default="keys_native", type=str, help="Output Directory"
    )
    args = parser.parse_args()

    generate_and_save_keys(args.N, args.t, args.dir)


if __name__ == "__main__":
    run()

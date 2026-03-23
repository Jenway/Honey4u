from dataclasses import dataclass

try:
    import honey_native
except Exception as err:
    print(err)
    exit(-1)


@dataclass
class SigPublicMaterial:
    players: int
    threshold: int
    params_bin: bytes
    helper_share_bin: bytes


@dataclass
class SigPrivateMaterial:
    player_id: int  # 0-based
    params_bin: bytes
    share_bin: bytes


def sign(sk: SigPrivateMaterial, msg: bytes) -> bytes:
    signer = honey_native.ThresholdSigner(sk.player_id + 1, sk.params_bin, sk.share_bin)
    return signer.sign(msg)


def verify_share(pk: SigPublicMaterial, sig_bin: bytes, player_id: int, msg: bytes) -> bool:
    helper = honey_native.ThresholdSigner(1, pk.params_bin, pk.helper_share_bin)
    return helper.verify_share(player_id + 1, sig_bin, msg)


def combine_shares(pk: SigPublicMaterial, sigs: dict[int, bytes], msg: bytes) -> bytes:
    share_vec = [(j + 1, sig) for j, sig in sigs.items()]
    helper = honey_native.ThresholdSigner(1, pk.params_bin, pk.helper_share_bin)
    return helper.combine_shares(share_vec, msg)


def dealer(
    players: int, threshold: int, seed: None = None
) -> tuple[SigPublicMaterial, list[SigPrivateMaterial]]:
    _ = seed
    params_bin, shares_bin = honey_native.sig_generate_keys(players, threshold)
    pub = SigPublicMaterial(players, threshold, params_bin, shares_bin[0])
    priv = [
        SigPrivateMaterial(player_id=i, params_bin=params_bin, share_bin=shares_bin[i])
        for i in range(players)
    ]
    return pub, priv

from __future__ import annotations

from honey.crypto import ecdsa, pke, sig


def build_materials(num_nodes: int, faulty: int):
    sig_pk, sig_shares = sig.generate(num_nodes, faulty + 1)
    enc_pk, enc_shares = pke.generate(num_nodes, faulty + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(num_nodes)
    return sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks


def build_dumbo_materials(num_nodes: int, faulty: int):
    coin_pk, coin_shares = sig.generate(num_nodes, faulty + 1)
    proof_pk, proof_shares = sig.generate(num_nodes, num_nodes - faulty)
    enc_pk, enc_shares = pke.generate(num_nodes, faulty + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(num_nodes)
    return coin_pk, coin_shares, proof_pk, proof_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks

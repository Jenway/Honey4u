import asyncio
import logging
import os
import pickle
import time

from crypto import threshenc as tpke

logger = logging.getLogger(__name__)


async def honeybadger_block(
    pid: int,
    N: int,
    f: int,
    PK,
    SK,
    propose_queue: asyncio.Queue,
    acs_input_queue: asyncio.Queue,
    acs_output_queue: asyncio.Queue,
    tpke_bcast_queue: asyncio.Queue,
    tpke_recv_queue: asyncio.Queue,
    logger=None,
) -> tuple:
    """The HoneyBadgerBFT algorithm for a single block

    :param int pid: my identifier
    :param int N: number of nodes
    :param int f: fault tolerance
    :param PK: threshold encryption public key
    :param SK: threshold encryption secret key
    :param asyncio.Queue propose_queue: queue containing input transactions
    :param asyncio.Queue acs_input_queue: queue to provide input to ACS
    :param asyncio.Queue acs_output_queue: queue receiving ACS output array
    :param asyncio.Queue tpke_bcast_queue: queue to broadcast decryption shares
    :param asyncio.Queue tpke_recv_queue: queue receiving decryption shares
    :return: tuple of decrypted values
    """

    # Broadcast inputs are of the form (encrypted_key_ct, encrypted_payload)

    # Threshold encrypt
    tpke_t = time.time()
    propose = await propose_queue.get()

    key = os.urandom(32)  # random 256-bit key
    if isinstance(propose, str):
        propose = propose.encode()
    ciphertext = tpke.encrypt(key, propose)
    enc_key_ct = tpke.pke_encrypt(PK, key)

    to_acs = pickle.dumps((enc_key_ct, ciphertext))
    if logger is not None:
        logger.info("finish tpke in %f seconds" % (time.time() - tpke_t))

    await acs_input_queue.put(to_acs)

    # Wait for the corresponding ACS to finish
    vall = await acs_output_queue.get()

    # TODO: here skip the following checks since ACS might not return N-f values
    assert len(vall) == N
    assert len([_ for _ in vall if _ is not None]) >= N - f  # This many must succeed

    # Broadcast all our decryption shares
    my_shares = []
    for v in vall:
        if v is None:
            my_shares.append(None)
            continue
        (enc_key_ct_i, _ciph) = pickle.loads(v)
        share = tpke.pke_decrypt_share(SK, enc_key_ct_i)
        my_shares.append(share)

    await tpke_bcast_queue.put(my_shares)

    # Receive everyone's shares
    shares_received = {}
    while len(shares_received) < f + 1:
        (j, raw_shares) = await tpke_recv_queue.get()
        if j in shares_received:
            # TODO: alert that we received a duplicate
            logger and logger.warning(f"Received a duplicate decryption share from {j}")
            continue
        shares_received[j] = raw_shares

    assert len(shares_received) >= f + 1
    # TODO: Accountability
    # If decryption fails at this point, we will have evidence of misbehavior,
    # but then we should wait for more decryption shares and try again
    decryptions = []
    for i, v in enumerate(vall):
        if v is None:
            continue
        svec = {}
        for j, shares in shares_received.items():
            svec[j] = shares[i]  # Party j's share of broadcast i
        (enc_key_ct_i, ciph) = pickle.loads(v)
        key_shares = [share for share in svec.values() if share is not None]
        key = tpke.pke_combine_shares(PK, enc_key_ct_i, key_shares)
        plain = tpke.decrypt(key, ciph)
        decryptions.append(plain)

    return tuple(decryptions)

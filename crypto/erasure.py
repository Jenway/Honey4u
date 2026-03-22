import zfec


#####################
#    zfec encode    #
#####################
def encode(K, N, m):
    """Erasure encodes string ``m`` into ``N`` blocks, such that any ``K``
    can reconstruct.

    :param int K: K
    :param int N: number of blocks to encode string ``m`` into.
    :param bytes m: bytestring to encode.

    :return list: Erasure codes resulting from encoding ``m`` into
        ``N`` blocks using ``zfec`` lib.

    """
    try:
        m = m.encode()
    except AttributeError:
        pass
    encoder = zfec.Encoder(K, N)
    assert K <= 256  # TODO: Record this assumption!
    # pad m to a multiple of K bytes
    padlen = K - (len(m) % K)
    m += padlen * chr(K - padlen).encode()
    step = len(m) // K
    blocks = [m[i * step : (i + 1) * step] for i in range(K)]
    stripes = encoder.encode(blocks)
    return stripes


def decode(K, N, stripes):
    """Decodes an erasure-encoded string from a subset of stripes

    :param list stripes: a container of :math:`N` elements,
        each of which is either a string or ``None``
        at least :math:`K` elements are strings
        all string elements are the same length

    """
    assert len(stripes) == N
    blocks = []
    blocknums = []
    for i, block in enumerate(stripes):
        if block is None:
            continue
        blocks.append(block)
        blocknums.append(i)
        if len(blocks) == K:
            break
    else:
        raise ValueError("Too few to recover")
    decoder = zfec.Decoder(K, N)
    rec = decoder.decode(blocks, blocknums)
    m = b"".join(rec)
    padlen = K - m[-1]
    m = m[:-padlen]
    return m

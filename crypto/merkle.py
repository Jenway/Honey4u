import hashlib
import math


#####################
#    Merkle tree    #
#####################
def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def ceil(x):
    return int(math.ceil(x))


def merkleTree(strList):
    """Builds a merkle tree from a list of :math:`N` strings (:math:`N`
    at least 1)

    :return list: Merkle tree, a list of ``2*ceil(N)`` strings. The root
         digest is at ``tree[1]``, ``tree[0]`` is blank.

    """
    N = len(strList)
    assert N >= 1
    bottomrow = 2 ** ceil(math.log(N, 2))
    mt = [b""] * (2 * bottomrow)
    for i in range(N):
        mt[bottomrow + i] = hash(strList[i])
    for i in range(bottomrow - 1, 0, -1):
        mt[i] = hash(mt[i * 2] + mt[i * 2 + 1])
    return mt


def getMerkleBranch(index, mt):
    """Computes a merkle tree from a list of leaves."""
    res = []
    t = index + (len(mt) >> 1)
    while t > 1:
        res.append(mt[t ^ 1])  # we are picking up the sibling
        t //= 2
    return res


def merkleVerify(N, val, roothash, branch, index):
    """Verify a merkle tree branch proof"""
    assert 0 <= index < N
    # XXX Python 3 related issue, for now let's tolerate both bytes and
    # strings
    assert isinstance(val, (str, bytes))
    assert len(branch) == ceil(math.log(N, 2))
    # Index has information on whether we are facing a left sibling or a right sibling
    tmp = hash(val)
    tindex = index
    for br in branch:
        tmp = hash((tindex & 1) and br + tmp or tmp + br)
        tindex >>= 1
    if tmp != roothash:
        print("Verification failed with", hash(val), roothash, branch, tmp == roothash)
        return False
    return True

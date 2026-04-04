"""Test broadcast mempool functionality"""

import time

from honey.data.broadcast_mempool import BroadcastMempool


def _add_payload(
    mempool: BroadcastMempool,
    *,
    payload: bytes = b"test_data",
    roothash: bytes = b"test_hash",
    round_no: int = 0,
    sender_id: int = 0,
    shards: list[bytes] | None = None,
    proofs: list[bytes] | None = None,
) -> str:
    return mempool.add(
        payload,
        roothash,
        shards or [b"s0", b"s1", b"s2", b"s3"],
        proofs or [b"p0", b"p1", b"p2", b"p3"],
        round_no,
        sender_id,
        time.time(),
    )


def test_mempool_add_and_get():
    """Test basic add and get operations"""
    mempool = BroadcastMempool(max_size=100, expire_rounds=5)

    payload = b"test_data"
    roothash = b"test_hash"
    shards = [b"shard0", b"shard1", b"shard2", b"shard3"]
    proofs = [b"proof0", b"proof1", b"proof2", b"proof3"]
    round_no = 0
    sender_id = 0

    payload_id = _add_payload(
        mempool,
        payload=payload,
        roothash=roothash,
        round_no=round_no,
        sender_id=sender_id,
        shards=shards,
        proofs=proofs,
    )

    data = mempool.get(payload_id)
    assert data is not None
    assert data.payload == payload
    assert data.roothash == roothash
    assert data.round_no == round_no
    assert data.sender_id == sender_id


def test_mempool_get_by_hash():
    """Test retrieval by merkle hash"""
    mempool = BroadcastMempool()

    payload = b"test_data"
    roothash = b"test_hash"

    _add_payload(mempool, payload=payload, roothash=roothash)

    data = mempool.get_by_hash(roothash)
    assert data is not None
    assert data.payload == payload


def test_mempool_get_by_round_sender():
    """Test retrieval by round and sender"""
    mempool = BroadcastMempool()

    payload = b"test_data"
    round_no = 2
    sender_id = 3

    _add_payload(mempool, payload=payload, round_no=round_no, sender_id=sender_id)

    data = mempool.get_by_round_sender(round_no, sender_id)
    assert data is not None
    assert data.payload == payload


def test_mempool_list_round():
    """Test listing all payloads for a round"""
    mempool = BroadcastMempool()

    round_no = 1
    for sender in range(4):
        _add_payload(
            mempool,
            payload=f"data_{sender}".encode(),
            roothash=f"hash_{sender}".encode(),
            round_no=round_no,
            sender_id=sender,
            shards=[b"s0", b"s1"],
            proofs=[b"p0", b"p1"],
        )

    payloads = mempool.list_round(round_no)
    assert len(payloads) == 4
    assert all(sender in payloads for sender in range(4))


def test_mempool_list_unused():
    """Test finding unused payloads"""
    mempool = BroadcastMempool()

    round_no = 1
    for sender in range(4):
        _add_payload(
            mempool,
            payload=f"data_{sender}".encode(),
            roothash=f"hash_{sender}".encode(),
            round_no=round_no,
            sender_id=sender,
            shards=[b"s0", b"s1"],
            proofs=[b"p0", b"p1"],
        )

    selected = {0, 1}
    unused = mempool.list_unused(round_no, selected)

    assert len(unused) == 2
    unused_senders = {sender for sender, _ in unused}
    assert unused_senders == {2, 3}


def test_mempool_cleanup():
    """Test cleanup of expired entries"""
    mempool = BroadcastMempool(max_size=100, expire_rounds=2)

    for round_no in range(4):
        _add_payload(
            mempool,
            payload=f"data_{round_no}".encode(),
            roothash=f"hash_{round_no}".encode(),
            round_no=round_no,
            shards=[b"s0"],
            proofs=[b"p0"],
        )

    mempool.cleanup(3)

    stats = mempool.stats()
    assert len(stats["rounds_covered"]) == 3
    assert 0 not in stats["rounds_covered"]
    assert 1 in stats["rounds_covered"]


def test_mempool_lru_eviction():
    """Test LRU eviction when max_size is exceeded"""
    mempool = BroadcastMempool(max_size=3, expire_rounds=10)

    ids = []
    for i in range(4):
        pid = _add_payload(
            mempool,
            payload=f"data_{i}".encode(),
            roothash=f"hash_{i}".encode(),
            sender_id=i,
            shards=[b"s0"],
            proofs=[b"p0"],
        )
        ids.append(pid)

    assert mempool.get(ids[0]) is None
    assert mempool.get(ids[1]) is not None
    assert mempool.get(ids[2]) is not None
    assert mempool.get(ids[3]) is not None


def test_mempool_access_refreshes_lru_order():
    """Test that reads refresh LRU order before eviction."""
    mempool = BroadcastMempool(max_size=3, expire_rounds=10)

    ids = [
        _add_payload(
            mempool,
            payload=f"data_{i}".encode(),
            roothash=f"hash_{i}".encode(),
            sender_id=i,
            shards=[b"s0"],
            proofs=[b"p0"],
        )
        for i in range(3)
    ]

    assert mempool.get(ids[0]) is not None

    newest_id = _add_payload(
        mempool,
        payload=b"data_3",
        roothash=b"hash_3",
        sender_id=3,
        shards=[b"s0"],
        proofs=[b"p0"],
    )

    assert mempool.get(ids[0]) is not None
    assert mempool.get(ids[1]) is None
    assert mempool.get(ids[2]) is not None
    assert mempool.get(newest_id) is not None


def test_mempool_stats():
    """Test statistics reporting"""
    mempool = BroadcastMempool()

    stats_empty = mempool.stats()
    assert stats_empty["size"] == 0

    for round_no in range(3):
        for sender in range(2):
            _add_payload(
                mempool,
                payload=f"data_{round_no}_{sender}".encode(),
                roothash=f"hash_{round_no}_{sender}".encode(),
                round_no=round_no,
                sender_id=sender,
                shards=[b"s0"],
                proofs=[b"p0"],
            )

    stats = mempool.stats()
    assert stats["size"] == 6
    assert stats["oldest_round"] == 0
    assert stats["newest_round"] == 2
    assert len(stats["rounds_covered"]) == 3
